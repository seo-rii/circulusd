# 오프라인 멀티테넌트 Pi 에이전트 플랫폼 기술 스펙

- **문서 상태:** Draft v0.3
- **기준일:** 2026-08-22
- **개정 사유:** v0.2 설계 리뷰 반영
- **배포 형태:** 완전 오프라인 셀프호스팅
- **핵심 기술:** Pi Agent Core, stock workerd, celld, Computer-inspired Workspace, sandboxd, NsJail, Docker, Firecracker
- **주요 목표:** 사용자별 Pi 및 extension lifecycle 완전 분리, 선택형 실행 환경, 간단한 설치, 확장 가능한 MCP·바이너리 연동

### v0.3 주요 변경점

- AgentEngine ↔ SessionHost 이벤트/커밋 프로토콜과 `AgentEvent`/`AgentCheckpoint` 스키마를 명시 (§9.2.1–9.2.2)
- turn당 순차 effect 불변식을 명문화하고 병렬 tool call의 결정적 직렬화 규칙을 도입 (§9.2.3, §15.3, 불변식 36)
- TurnAuthority TTL을 신규 broker call admission의 상한으로 한정하고 lease-bound mid-turn renewal을 정의하여 장기 native command(TTL 초과)와의 모순을 해소 (§29.7, §46.1)
- workspace manifest를 대형 트리에 맞게 directory 단위 tree object 구조로 확장하고 path 정규화/한계 규칙을 명시 (§17.4)
- overlayfs upperdir 기반 가속 diff 경로와 backend별 materialization 전송(Firecracker는 host-built block image)을 명시 (§17.5, §17.8)
- workspace write lease 대기 정책과 read-only invocation 경로를 추가 (§18.1, §18.6)
- celld state plane에 요구하는 내구성 계약(단일 writer, commit durability, 복제 RPO)과 백업 RPO/RTO 목표를 명문화 (§15.8, §44.3)
- MCP protocol version pin, server-initiated request 기본 거부, notification/resources 정책을 추가 (§27.6)
- 인증 모델(local account/PAT/선택적 LAN IdP), 시간 동기화, kernel baseline, audit tamper resistance를 강화 (§37.10, §40.4, §44.1, §48.4)
- 데이터 삭제/export semantics, blob upload quota reservation, 증분 GC 절차, ExtensionState migration 체이닝 규칙을 명시 (§36.12, §17.6, §16.4, §11.7)
- 주요 위험 표, acceptance test, 최종 불변식(36–38)을 위 변경에 맞춰 갱신 (§52, §53, §55)
- release/bundle 예시 버전을 0.3.0으로 갱신하고 architecture별 bundle 정책을 명시 (§42)

### v0.2 주요 변경점

- Session DO를 turn/effect durable state machine의 단일 authority로 고정
- Pi와 플랫폼이 중복 operation state machine을 갖지 않도록 `AgentEngine` 경계 도입
- Worker Loader에 compatibility date/flags/resource limit 및 content-addressed Worker identity 명시
- capability를 장기 bearer token이 아닌 stable broker binding + per-turn authority 모델로 변경
- Workspace commit에 invocation ledger, request digest, commit ID와 crash recovery protocol 도입
- extension별 native package를 `ExecutionEnvironmentRevision`으로 합성하는 모델 도입
- 일회성 `exec()` 중심 API를 장기 process/stdin MCP를 지원하는 `spawn/attach/writeStdin/wait` 모델로 확장
- upstream `computerd`를 core dependency에서 제거하고 최소 공통 guest/container agent인 `sandboxd` 도입
- NsJail을 저오버헤드 native execution backend로 추가
- Runtime Revision 교체를 candidate → health check → CAS activation 방식의 staged activation으로 변경
- workspace manifest/content-addressed blob, ACL/quota/GC, API idempotency와 SSE replay를 명시
- host daemon은 Go, Worker/state/extension runtime은 TypeScript를 기본 구현 언어로 고정

---

## 1. 개요

본 시스템은 여러 사용자가 각자 독립적인 Pi 에이전트와 extension 조합을 구성하여 사용할 수 있는 완전 오프라인 셀프호스팅 챗봇 서버다.

각 세션은 다음 요소를 독립적으로 가진다.

- Pi 인스턴스
- extension 집합
- extension lifecycle hook graph
- extension 전역 상태
- 시스템 프롬프트와 모델 설정
- MCP 연결 설정
- workspace 연결
- native execution backend
- 보안 정책과 리소스 제한

가장 중요한 실행 불변식은 다음과 같다.

> **하나의 세션은 하나의 Dynamic Worker isolate, 하나의 Pi 인스턴스, 하나의 extension graph를 가진다.**

```text
one session
    =
one workerd Dynamic Worker isolate
    =
one Pi instance
    =
one extension set
    =
one lifecycle-hook graph
```

같은 사용자가 여러 대화를 동시에 실행하더라도 각 대화는 별도의 Pi isolate를 가진다.

```text
User A
├── Session A1
│   └── Pi Worker isolate
│       ├── Extension X
│       └── Extension Y
│
└── Session A2
    └── Pi Worker isolate
        ├── Extension X
        └── Extension Z
```

사용자가 선택한 extension은 해당 세션의 Pi Worker 안에서 직접 로드한다. 따라서 기존 Pi extension이 사용하는 lifecycle hook, 전역 상태, 도구 등록, 메시지 변환을 세션별로 자연스럽게 분리할 수 있다.

다만 Pi Worker는 **durable authority가 아니다**. 대화, turn의 durable program counter, 외부 effect의 intent/settlement, runtime pointer, 완료된 tool 결과는 Session DO가 권위 있는 상태로 보유한다. Pi는 이 상태를 읽어 한 단계씩 실행하는 `AgentEngine` 역할을 맡는다.

Native process는 Pi Worker 내부에서 직접 실행하지 않는다. 모든 native process는 다음 세 backend 중 정책에 맞는 `ExecutionProvider`를 통해 실행한다.

- `nsjail`: Linux namespace/seccomp/cgroup 기반의 저오버헤드 process sandbox
- `docker`: OCI container 기반의 범용 sandbox
- `firecracker`: 별도 guest kernel을 갖는 microVM sandbox

`nsjail`과 Docker는 모두 host kernel을 공유한다. 따라서 hostile native code에 대해 host-kernel escape까지 포함한 강한 경계를 요구하면 Firecracker를 선택해야 한다.

또한 workerd isolate만 사용하는 agent 모드는 V8/workerd runtime escape 위험을 수용하는 저비용 격리 모드다. 악의적 JavaScript extension을 실행해야 할 경우에는 workerd process 자체를 별도의 OS/VM 경계에 넣는다.

## 2. 핵심 설계 결정

| 항목 | 결정 |
|---|---|
| Pi 실행 단위 | 세션별 Dynamic Worker isolate |
| Pi 실행 책임 | 모델/도구 step 실행; durable turn state의 authority가 아님 |
| Durable turn/effect authority | celld의 Session Durable Object |
| Extension 위치 | 해당 세션 Pi Worker 안에 직접 로드 |
| Extension 설정 변경 | 기존 isolate 수정이 아니라 새 Runtime Revision 생성 |
| Runtime 교체 | candidate 생성 → read-only health check → CAS activation → old drain |
| Pi Worker 역할 | 재생성 가능한 실행 캐시 |
| Workspace authoritative state | celld의 Workspace DO + content-addressed blob store |
| Sandbox filesystem | Workspace DO의 일시적인 projection |
| Native execution | NsJail, Docker 또는 Firecracker |
| 기본 reference backend | Docker; lightweight profile에서는 NsJail |
| 강화된 native backend | Firecracker |
| Native package resolution | extension 요구사항 합집합을 `ExecutionEnvironmentRevision`으로 resolve |
| Sandbox control agent | 공통 `sandboxd`; upstream computerd는 optional experimental provider |
| Agent 격리와 native 격리 | 서로 독립적인 설정 |
| Capability | stable broker binding + 짧은 per-turn authority |
| 외부 effect 보장 | prepare → dispatch → external commit → settle; exactly-once 가정 금지 |
| 외부 네트워크 | 기본 차단 |
| MCP | 중앙 MCP Gateway 경유 |
| stdio MCP | 선택된 NsJail/Docker/Firecracker 환경 안의 장기 process로 실행 |
| 설치 | 단일 air-gap bundle과 `platformctl` |
| 구현 언어 | host daemon/CLI는 Go, Worker/state/extension runtime은 TypeScript |
| 기본 배포 | 단일 노드 |
| 확장 배포 | state, agent, compute node 분리 가능 |
| Turn 내 effect 동시성 | 한 시점에 최대 하나의 in-flight external effect; 병렬 tool call은 결정적 직렬화 |
| Turn Authority 수명 | 짧은 TTL(신규 admission 상한) + lease-bound mid-turn renewal |
| Workspace diff | full-scan을 correctness baseline으로, overlayfs upperdir를 가속 경로로 |

### 단일 durable program counter 원칙

Session/turn 하나에 durable한 실행 위치를 나타내는 상태기계가 둘 이상 존재해서는 안 된다.

초기 구현에서는 다음 모델을 사용한다.

```text
Session DO
  └── authoritative turn/effect state machine
        │
        ▼
Pi AgentEngine
  └── one-step execution kernel
```

향후 upstream Pi `AgentHarness`가 필요한 restore/hook 경로를 안정적으로 제공하여 이를 채택하더라도, 플랫폼에 두 번째 operation journal을 추가해서는 안 된다. 그 경우 Session DO는 AgentHarness가 사용하는 durable storage backend가 되며, 상태기계 authority는 하나로 유지해야 한다.

## 3. 목표

### 3.1 기능 목표

시스템은 다음 기능을 제공해야 한다.

1. 사용자별 extension 선택 및 설정
2. 세션별 Pi 및 lifecycle hook 완전 분리
3. 사용자별 시스템 프롬프트와 모델 설정
4. 파일을 영속적으로 관리하는 workspace
5. NsJail, Docker, Firecracker 중 native 실행 환경 선택
6. Python, Node.js, LibreOffice, ffmpeg 등 native binary 실행
7. local stdio MCP와 LAN Streamable HTTP MCP 연결
8. 사용자별 권한, 리소스 제한, 네트워크 정책
9. 오프라인 설치와 업그레이드
10. 세션 및 sandbox 장애 이후 상태 복구
11. 외부 side effect의 crash-consistent replay/confirmation 정책
12. 향후 브라우저, CUA, PPT, Excel 등의 실행기 추가
13. 단일 노드에서 시작하여 여러 노드로 확장

### 3.2 보안 목표

- 정상적인 extension 코드 경로를 통한 세션 간 메모리 접근 방지
- 다른 사용자의 설정, lifecycle hook, tool registry 접근 방지
- 다른 workspace 접근 방지
- extension의 임의 네트워크 접근 방지
- native binary에 대한 CPU, 메모리, PID, 디스크, 시간 제한
- secret 값을 extension에 직접 노출하지 않는 구조
- Docker daemon socket과 `/dev/kvm`, host namespace control API의 사용자 코드 노출 방지
- stale turn, stale agent shard, stale sandbox의 요청을 fencing으로 거부
- 손상된 agent shard 또는 sandbox의 즉시 폐기 가능성
- 보안 수준과 비용 사이의 명시적인 선택 제공
- shared-kernel backend(NsJail/Docker)와 microVM backend(Firecracker)의 경계를 UI와 audit에서 명확히 표시

### 3.3 운영 목표

- 인터넷 연결 없이 설치 가능
- 단일 명령으로 초기 설치
- NsJail-only, Docker-only, Firecracker-only, Full 구성을 지원
- 하나의 기본 설정 파일로 운영 가능
- 자동 사전 점검과 통합 진단 제공
- 주요 바이너리, rootfs, image, kernel의 digest 고정
- 롤백 가능한 업그레이드
- authoritative state와 ephemeral cache를 명확히 분리

### 3.4 성능 목표

- 짧은 native 명령은 NsJail backend에서 container daemon round-trip 없이 낮은 시작 지연을 목표로 한다.
- 동일 workspace의 sandbox는 정책이 허용하는 범위에서 재사용할 수 있다.
- workerd shard와 sandbox cache는 메모리 압력 시 언제든 폐기할 수 있어야 한다.
- 성능 최적화가 durable correctness 또는 fencing을 우회해서는 안 된다.

## 4. 비목표

초기 버전에서는 다음을 목표로 하지 않는다.

- shared workerd mode에서 악의적 extension에 대한 완전한 VM 수준 보안
- NsJail 또는 Docker에서 host-kernel escape에 대한 VM 수준 보안 제공
- 실행 중인 Linux 프로세스의 NsJail↔Docker↔Firecracker 실시간 이전
- 서로 다른 session의 Pi 인스턴스 공유
- 기존 Pi CLI 전체를 수정 없이 workerd에서 실행
- Pi와 플랫폼이 각각 별도의 durable turn state machine을 유지하는 구조
- extension의 임의 Node.js builtin 사용
- 사용자가 Docker socket, NsJail launcher privilege, Firecracker API를 직접 호출하는 기능
- 인터넷 extension marketplace
- 범용 Kubernetes scheduler
- Windows 또는 macOS 호스트 지원
- native sandbox 안의 프로세스 상태 영속화
- 분산 파일시스템 자체 구현
- 동적 OCI layer 합성 또는 매 turn마다 custom rootfs를 빌드하는 기능
- exactly-once external side effect 보장
- 하나의 turn 안에서 복수 external effect의 병렬 실행 (§9.2.3의 직렬화 규칙으로 대체)
- workspace write lease의 path 단위 분할

## 5. 용어

| 용어 | 의미 |
|---|---|
| Tenant | 하나의 조직 또는 보안 경계 |
| User | Tenant에 소속된 사용자 |
| Workspace | 영속적인 파일 및 프로젝트 상태 |
| Session | 하나의 대화 및 Pi 실행 단위 |
| Turn | Session 안의 하나의 사용자 입력부터 terminal assistant 결과까지의 durable operation |
| Effect | model call, tool call, workspace commit 등 Session 밖에서 결과가 발생할 수 있는 작업 |
| Runtime Revision | extension, 설정, prompt, workerd compatibility와 policy를 고정한 불변 agent 실행 버전 |
| Runtime Pointer | active/candidate/previous Runtime Revision을 가리키는 Session DO 상태 |
| Agent Bundle | Pi runtime과 선택된 extension 모듈의 묶음 |
| AgentEngine | Session DO의 durable state를 입력으로 받아 Pi step을 실행하는 adapter 경계 |
| Pi Worker | 세션별로 생성되는 Dynamic Worker |
| Agent Placement | Pi Worker가 배치되는 workerd process 및 optional outer sandbox 정책 |
| Execution Backend | native process를 실행하는 `nsjail`, `docker`, `firecracker` provider |
| Execution Environment Revision | 여러 extension의 native package 요구를 합성한 immutable toolchain 환경 |
| Sandbox | native binary 또는 고위험 workerd를 격리하는 실행 환경 |
| sandboxd | sandbox 내부에서 process lifecycle과 workspace projection을 중개하는 최소 공통 agent |
| Workspace DO | authoritative workspace metadata/revision state를 저장하는 celld 객체 |
| Workspace Blob | content-addressed file content object |
| Workspace Commit | base revision, mutation set, invocation ID를 검증해 새 revision을 만드는 원자적 변경 |
| Invocation Ledger | 동일 invocation의 외부 commit 중복 적용을 막고 이전 결과를 조회하는 durable 기록 |
| Stable Broker Binding | Pi Worker에 주입되는 장기 수명의 RPC binding; bearer secret이 아님 |
| Turn Authority | 현재 turn/placement/policy generation에 묶인 짧은 권한 객체 |
| Capability | 특정 주체가 제한된 서비스 동작을 수행하도록 하는 권한 모델의 총칭 |
| Broker | authority를 검증하고 실제 서비스 호출을 중개하는 플랫폼 구성요소 |
| Fencing Generation | stale owner/worker/sandbox의 늦은 write를 거부하기 위한 단조 증가 generation |
| AgentEvent | AgentEngine이 SessionHost에 전달하는 이벤트 단위; durable event와 ephemeral event로 구분 |
| AgentCheckpoint | turn durable program counter의 engine-opaque payload와 플랫폼 소유 envelope |
| Read-only Invocation | write lease 없이 고정 revision snapshot에서 실행되는 native 실행 경로 |

이 문서에서 다음 용어를 규범적으로 사용한다.

- **MUST:** 반드시 구현
- **MUST NOT:** 구현 금지
- **SHOULD:** 특별한 이유가 없다면 구현
- **MAY:** 선택 구현

## 6. 전체 아키텍처

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         Client / Web UI                             │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ HTTPS / SSE / WebSocket
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           platformd                                 │
│                                                                     │
│ API Gateway        Auth / Tenant / ACL     Session Scheduler        │
│ Policy Engine      Extension Registry      Capability Broker        │
│ Model Gateway      MCP Gateway             Artifact / Secret        │
└───────────────┬─────────────────┬───────────────────┬───────────────┘
                │                 │                   │
                ▼                 ▼                   ▼
┌─────────────────────┐  ┌───────────────────┐  ┌─────────────────────┐
│        celld        │  │ agentd / workerd  │  │      executord      │
│                     │  │                   │  │                     │
│ User DO             │  │ SessionHost       │  │ NsJailProvider      │
│ Session DO          │  │ Worker Loader     │  │ DockerProvider      │
│ Workspace DO        │  │                   │  │ FirecrackerProvider │
│ ExtensionState DO   │  │ Pi session A      │  └──────────┬──────────┘
│ Audit DO            │  │ Pi session B      │             │
└──────────┬──────────┘  └─────────┬─────────┘             │
           │                       │ stable bindings        │
           │                       │ + turn authority       │
           │                       └───────────────┬─────────┘
           │                                       │
           ▼                                       ▼
┌─────────────────────┐               ┌────────────────────────────────┐
│ Validated Object    │               │        Native Sandboxes         │
│ Store               │               │                                │
│                     │               │ NsJail jail                     │
│ celld-state         │               │ └── sandboxd                    │
│ workspace-blobs     │               │                                │
│ artifacts           │               │ Docker container               │
│ bundles             │               │ └── sandboxd                    │
│ backups             │               │                                │
└─────────────────────┘               │ Firecracker microVM            │
                                      │ └── sandboxd                    │
                                      └────────────────────────────────┘
```

### 6.1 권한 분리

`platformd`는 Docker socket, `/dev/kvm`, host mount namespace 조작 권한을 가져서는 안 된다. 이러한 권한은 `executord`에만 존재한다.

`agentd`는 workerd process와 cgroup을 관리하지만 Worker Loader API를 직접 호출하지 않는다. Worker Loader는 workerd 안의 trusted TypeScript `SessionHost` Worker가 호출한다.

```text
agentd (Go)
  └── workerd process
       └── SessionHost Worker (trusted TS)
            └── LOADER.get(...)
                 └── Dynamic Pi Worker
```

### 6.2 상태와 실행 경계

```text
Durable authority
├── Session DO       conversation / turn / effect / runtime pointer
├── Workspace DO     tree metadata / revision / lease / invocation ledger
├── Object Store     file blobs / bundles / artifacts / replicated celld state
└── ExtensionState   versioned persistent extension state

Ephemeral cache
├── Dynamic Pi Worker
├── workerd shard
├── sandboxd process
├── NsJail jail
├── Docker container
└── Firecracker microVM
```

Ephemeral component의 손실만으로 durable operation의 성공 여부가 바뀌어서는 안 된다.

## 7. 격리 모델

본 시스템은 Agent Isolation과 Native Execution Isolation을 독립적으로 관리한다. 두 축을 섞어 하나의 "보안 등급"으로 표현해서는 안 된다.

### 7.1 Agent Isolation

Agent Isolation은 Pi와 JavaScript/Wasm extension이 어느 workerd process와 outer sandbox를 공유하는지 결정한다.

```text
Pi Worker
├── lifecycle hooks
├── extension globals
├── tool registry
├── message transforms
└── extension-local ephemeral state
```

Agent Isolation의 두 축은 다음과 같다.

```yaml
agentIsolation:
  processScope: shared   # shared | tenant | session
  outerIsolation: none  # none | nsjail | docker | firecracker
```

- `processScope`는 V8/workerd escape 시 blast radius를 결정한다.
- `outerIsolation`은 workerd process를 host kernel/VM 경계 안에 추가로 넣을지 결정한다.
- unreviewed hostile extension의 reference policy는 `processScope=session`, `outerIsolation=firecracker`다.

### 7.2 Native Execution Isolation

Native Execution Isolation은 Python, ffmpeg, LibreOffice, 브라우저, stdio MCP 등 native process의 경계를 결정한다.

```text
native execution
├── Python
├── Node.js
├── ffmpeg
├── LibreOffice
├── Chromium
└── stdio MCP server
```

지원 backend:

| Backend | 격리 경계 | 장점 | 주요 위험/제약 |
|---|---|---|---|
| `nsjail` | Linux namespaces + cgroup + seccomp, host kernel 공유 | 매우 낮은 시작 비용, daemon 불필요, 세밀한 syscall/mount 정책 | rootfs/image 관리 직접 필요, kernel escape는 host 영향 |
| `docker` | OCI container namespaces + cgroup + seccomp, host kernel 공유 | package/image 생태계, 운영 편의 | Docker daemon TCB, kernel escape는 host 영향 |
| `firecracker` | KVM microVM + guest kernel | host kernel과 guest workload 사이 강한 경계 | 메모리/부팅/이미지 관리 비용, KVM 필요 |

`nsjail`은 Docker와 같은 OCI container engine은 아니지만 플랫폼 관점에서는 동일한 `ExecutionProvider` contract를 구현하는 lightweight sandbox backend다.

### 7.3 두 축의 독립성

사용자가 Firecracker를 native backend로 선택해도 Pi extension 자체는 기본적으로 workerd 안에서 실행된다. 반대로 Pi Worker를 Firecracker에 넣더라도 native tool이 자동으로 Firecracker 안에서 실행되는 것은 아니다.

예:

```yaml
agentIsolation:
  processScope: tenant
  outerIsolation: none

execution:
  backend: firecracker
```

위 설정은 JavaScript extension은 tenant workerd process를 공유하고, native tool만 Firecracker에서 실행한다.

### 7.4 공유 kernel 위험

NsJail과 Docker는 서로 구현 방식은 다르지만 host kernel을 공유한다. 따라서 다음을 MUST 명시한다.

- UI와 audit에서 실제 backend 표시
- hostile native code의 기본 권장 backend는 Firecracker
- NsJail/Docker 선택은 host kernel attack surface를 수용하는 정책임을 문서화
- backend fallback으로 보안 수준을 낮추지 않음

## 8. Agent Placement Profile

모든 profile에서 세션마다 별도의 Dynamic Worker isolate를 사용한다. Profile은 실제로는 `processScope`와 `outerIsolation`의 조합이며, 아래 이름은 편의 alias다.

### 8.1 `shared-workerd`

```text
workerd process
├── Session A isolate
│   └── Pi + extensions
├── Session B isolate
│   └── Pi + extensions
└── Session C isolate
    └── Pi + extensions
```

정규화된 값:

```yaml
processScope: shared
outerIsolation: none
```

특성:

- 가장 낮은 리소스 사용량
- 세션별 global state와 lifecycle hook 분리
- 세션별 broker binding 분리
- 하나의 workerd process를 여러 tenant가 공유 가능
- workerd/V8 escape 시 같은 shard의 모든 resident session이 잠재적 영향 범위

사용 조건:

- 플랫폼이 직접 작성하거나 review한 extension
- 제한된 내부 사용자
- 높은 밀도가 중요한 환경

### 8.2 `tenant-workerd`

```text
workerd process for Tenant A
├── Session A1 isolate
└── Session A2 isolate

workerd process for Tenant B
├── Session B1 isolate
└── Session B2 isolate
```

```yaml
processScope: tenant
outerIsolation: none
```

특성:

- 세션별 isolate 유지
- tenant별 OS process
- runtime escape의 blast radius를 tenant 단위로 제한
- process별 cgroup CPU/memory limit 가능

### 8.3 `session-workerd`

```yaml
processScope: session
outerIsolation: none
```

세션마다 별도 workerd OS process를 사용한다. VM 경계는 아니지만 shard 간 메모리/프로세스 blast radius를 가장 작게 만든다.

### 8.4 `sandboxed-workerd`

workerd process 자체를 외부 sandbox에 넣는다.

```text
Outer Sandbox
└── workerd process
    └── one or more Pi session isolates
```

지원 outer isolation:

- `nsjail`: 낮은 오버헤드의 shared-kernel outer sandbox
- `docker`: OCI 운영 편의가 필요한 shared-kernel outer sandbox
- `firecracker`: hostile extension에 권장되는 guest-kernel 경계

고위험 extension의 reference profile:

```yaml
processScope: session
outerIsolation: firecracker
```

### 8.5 Trust class 기반 최소 정책

| Trust class | 최소 process scope | 최소 outer isolation |
|---|---|---|
| `platform-reviewed` | shared | none |
| `tenant-reviewed` | tenant | none |
| `signed-third-party` | tenant | nsjail 또는 docker |
| `unreviewed` | session | firecracker |

사용자는 자신의 정책을 더 강하게 만들 수 있지만 낮출 수 없다.

### 8.6 Shard 운영 정책

shared/tenant workerd는 다음 제한을 MUST 가진다.

- shard cgroup memory limit
- shard CPU quota
- 최대 resident session 수
- 최대 lifetime
- admission memory watermark
- OOM/heap pressure 이후 shard recycle
- source-map 기반 host-side stack remapping

per-isolate heap limit만으로 전체 shard RSS를 제어할 수 있다고 가정해서는 안 된다.

## 9. Pi 세션 실행 모델

### 9.1 세션과 Worker의 대응

Worker identity는 사람이 지정한 revision 문자열만으로 결정하지 않고 content-addressed runtime identity를 포함해야 한다.

```text
sessionId
+ runtimeRevisionDigest
+ piAdapterAbi
+ workerdCompatibility
            │
            ▼
pi/{sessionId}/{runtimeIdentityDigest}
            │
            ▼
Dynamic Worker isolate
```

예:

```text
pi/sess_01J8XYZ/sha256-68f0...
```

하나의 Pi Worker에는 다음이 포함된다.

```text
Pi Worker
├── platform AgentEngine adapter
├── selected Pi agent-core subset
├── selected extension modules
├── immutable extension configuration
├── immutable session configuration
├── lifecycle hook dispatcher
├── tool registry
└── stable scoped service bindings
```

### 9.2 Durable state ownership

초기 구현에서 Session DO가 turn과 effect의 유일한 durable state machine이다.

```text
Session DO state
      │
      │ exact durable program counter
      ▼
AgentEngine.step()
      │
      ├── model request intent
      ├── tool request intent
      └── internal Pi event
```

Pi runtime은 별도의 authoritative operation journal을 유지해서는 안 된다.

권장 interface:

```ts
interface AgentEngine {
  startTurn(ctx: StartTurnContext): AsyncIterable<AgentEvent>;
  resumeTurn(ctx: ResumeTurnContext): AsyncIterable<AgentEvent>;
  abortTurn(turnId: string): Promise<void>;
}
```

초기 구현체:

```text
LowLevelPiAgentEngine
```

향후 upstream AgentHarness를 채택할 경우:

```text
PiAgentHarnessEngine
```

단, 이 경우에도 플랫폼의 별도 turn program counter와 AgentHarness program counter를 동시에 authoritative하게 유지해서는 안 된다. Session DO/SessionStorage가 하나의 transaction domain으로 동작하도록 adapter를 재설계해야 한다.

#### 9.2.1 AgentEvent와 커밋 프로토콜

AgentEngine과 SessionHost 사이의 이벤트 스트림은 다음 discriminated union을 기본으로 한다.

```ts
type AgentEvent =
  | { type: "model_request"; request: ModelRequestIntent }
  | { type: "tool_request"; request: ToolRequestIntent }
  | { type: "assistant_delta"; delta: unknown }
  | { type: "checkpoint"; checkpoint: AgentCheckpoint }
  | { type: "turn_complete"; result: TurnResult }
  | { type: "turn_error"; error: AgentError };
```

`StartTurnContext`/`ResumeTurnContext`는 최소한 opaque TurnAuthority, 현재 AgentCheckpoint, 직전에 settle된 effect 결과를 포함한다.

커밋 규칙(MUST):

- `model_request`, `tool_request`, `checkpoint`, `turn_complete`, `turn_error`는 durable event다. SessionHost는 해당 event를 Session DO에 commit 완료하기 전까지 iterator의 다음 event를 요청해서는 안 된다. AsyncIterable의 pull 시점이 곧 backpressure 경계다.
- `assistant_delta`는 ephemeral이며 durable commit 없이 client stream으로 전달할 수 있다.
- durable commit 실패 시 SessionHost는 iteration을 중단하고 `abortTurn`을 호출한다. AgentEngine은 임의 시점의 iteration 중단을 가정해야 하며, 이는 §11.2의 replay semantics와 동일하다.
- AgentEngine은 하나의 external intent(`model_request`/`tool_request`)를 emit한 뒤 그 settlement 결과를 입력으로 받기 전까지 추가 external intent를 emit해서는 안 된다. 이것이 §15.3 순차 effect 불변식의 engine-side 표현이다.

#### 9.2.2 AgentCheckpoint

```ts
interface AgentCheckpoint {
  engineKind: "low-level" | "agent-harness";
  adapterAbiVersion: number;
  checkpointSchemaVersion: number;
  runtimeRevisionDigest: string;

  payload: unknown;          // engine-opaque
  payloadDigest: string;
}
```

- payload는 engine-opaque지만 envelope(위 필드)은 플랫폼이 소유한다.
- Session DO는 checkpoint를 turn state 전이와 같은 transaction으로 저장한다.
- resume 시 envelope의 `runtimeRevisionDigest`/`adapterAbiVersion`/`checkpointSchemaVersion`이 현재 active runtime identity와 호환되지 않으면 resume을 거부하고 turn을 `failed` 또는 `needs_confirmation`으로 종료한다. Runtime 전환은 turn 경계에서만 일어나므로(§12.3) 정상 경로에서는 발생하지 않는다.
- `checkpointSchemaVersion` 변경은 adapter ABI 변경으로 취급하며 §50.3 compatibility gate 대상이다.

#### 9.2.3 병렬 tool call의 직렬화

v0.3의 durable 실행 모델은 turn당 **한 시점에 최대 하나의 in-flight external effect**만 허용한다(§15.3, §35).

- model 응답이 복수 tool call을 포함하면 adapter는 model이 제시한 순서대로 결정적으로 직렬화하여 하나씩 `tool_request`로 emit한다. 대기 중인 tool call 목록은 checkpoint의 일부로 durable하게 유지한다.
- 각 tool 결과가 settle된 뒤에만 다음 tool_request가 admission된다.
- Model Gateway는 provider 응답의 tool call 순서를 보존해야 하며, 순서 정보가 없는 provider 형식에는 안정 정렬 규칙을 적용해 정규화한다.
- 병렬 effect 실행은 복수 active effect, per-effect settlement, workspace write lease 상호작용을 정의하는 명시적 스펙 개정 없이 도입해서는 안 된다.

### 9.3 Worker Loader 경계

`agentd`는 Go host daemon으로 workerd process와 cgroup을 감독한다. Worker Loader API는 workerd 안의 trusted `SessionHost` Worker만 호출한다.

개념적 정의:

```ts
const worker = await env.LOADER.get(
  `pi/${sessionId}/${runtimeIdentityDigest}`,
  async () => ({
    compatibilityDate: runtime.workerd.compatibilityDate,
    compatibilityFlags: runtime.workerd.compatibilityFlags,

    limits: {
      cpuMs: policy.agentCpuMs,
      subRequests: policy.agentSubrequestLimit,
    },

    mainModule: "runtime/main.mjs",
    modules: moduleGraph,

    env: {
      STATE: stableStateBroker,
      WORKSPACE: stableWorkspaceBroker,
      MODEL: stableModelBroker,
      MCP: stableMcpBroker,
      EXECUTOR: stableExecutorBroker,
      ARTIFACTS: stableArtifactBroker,
      EVENTS: stableEventBroker,
    },

    globalOutbound: null,
  }),
);
```

Worker Loader가 노출하는 resource limit과 별개로, `agentd`는 workerd process 전체를 cgroup으로 제한해야 한다. per-isolate memory hard limit을 전제로 설계해서는 안 된다.

### 9.4 Turn Authority 주입

Worker `env`에는 15분 후 만료되는 bearer token을 고정 주입하지 않는다. `env`에는 stable broker stub만 존재한다.

turn 시작 시 SessionHost가 opaque `TurnAuthority`를 생성하거나 Broker에서 발급받아 AgentEngine 호출 context에 전달한다.

```ts
interface TurnAuthorityClaims {
  sessionId: string;
  turnId: string;
  runtimeRevision: string;

  turnLeaseGeneration: number;
  placementGeneration: number;
  policyGeneration: number;

  deadline: number;
}
```

Extension은 raw claims를 수정할 수 없어야 한다. Broker는 각 호출에서 현재 generation과 deadline을 확인한다.

### 9.5 Pi Worker는 authoritative state가 아니다

Pi Worker는 언제든 종료되거나 다른 `agentd`에서 다시 만들어질 수 있어야 한다.

다음 정보는 Pi Worker에만 존재해서는 안 된다.

- 대화 기록
- turn durable program counter
- effect intent/settlement
- 현재 runtime pointer
- 선택 extension과 configuration digest
- extension persistent state
- workspace 파일
- 실행 backend 선택
- policy generation
- 완료된 tool invocation 결과

### 9.6 Worker cold start

```text
1. Session DO에서 active Runtime Revision과 placement generation 조회
2. Runtime Revision digest 검증
3. Agent Bundle 및 module graph digest 검증
4. Pi runtime 초기화
5. extension modules 로드
6. hook graph 결정 및 freeze
7. versioned extension persistent state 연결
8. Session DO에서 현재 turn/effect state 조회
9. stale authority가 없는 새 TurnAuthority 생성
10. 필요한 경우 AgentEngine resume
```

cold start는 extension `shutdown()`이 이전 Worker에서 실행되었다고 가정해서는 안 된다.

## 10. Pi 호환 범위

기존 Pi coding-agent 전체 CLI를 workerd에서 그대로 실행하는 것을 요구하지 않는다.

Pi의 전체 coding-agent 환경에는 파일시스템, 프로세스, TUI, Node.js 실행 환경을 전제로 하는 부분이 있을 수 있다. 플랫폼은 필요한 agent-core subset만 사용하고 직접적인 host 권한을 제공하지 않는다.

초기 구현:

```text
Pi low-level agent core / loop
    +
platform AgentEngine adapter
    +
restricted extension API
```

### 10.1 지원 extension 등급

| 등급 | 설명 | 지원 |
|---|---|---|
| `worker` | 순수 JS/Wasm, platform API만 사용 | 완전 지원 |
| `pi-server` | Pi lifecycle hook과 platform tool API 사용 | 완전 지원 |
| `node-compatible` | 검증된 제한적 compatibility layer 사용 | 조건부 지원 |
| `legacy-node` | 직접 fs, child_process, TUI 사용 | 재작성 또는 native-sidecar adapter 필요 |
| `native-sidecar` | 별도 binary 또는 stdio MCP 필요 | NsJail/Docker/Firecracker에서 실행 |

### 10.2 금지 API

Pi Worker 내부 extension은 다음 기능을 직접 사용해서는 안 된다.

- `child_process`
- host 파일시스템 접근
- 임의 TCP/UDP socket
- Docker socket
- NsJail launcher/control privilege
- `/dev/kvm`
- 임의 환경 변수 열람
- 동적 native addon
- 사용자 지정 바이너리 로드
- 임의 경로의 extension import
- 다른 session RPC endpoint 직접 접근

대신 다음 platform API를 사용한다.

```ts
ctx.workspace.readFile(path)
ctx.workspace.writeFile(path, data)
ctx.executor.spawn(request)
ctx.mcp.call(server, tool, input)
ctx.model.complete(request)
ctx.secrets.use(handle, request)
ctx.artifacts.create(data)
```

### 10.3 Hermetic bundle 조건

Extension bundle 생성은 단순 static import scan이 아니라 다음 pipeline을 거쳐야 한다.

```text
source
→ lockfile/dependency resolve
→ allowed module graph
→ dynamic import validation
→ forbidden builtin/native addon rejection
→ deterministic bundle
→ SBOM
→ digest
→ signature
```

`globalOutbound=null` acceptance test는 `fetch()`만이 아니라 WebSocket 및 raw socket 계열 API도 함께 검사해야 한다.

## 11. Extension lifecycle

### 11.1 Platform Extension API

플랫폼은 다음 lifecycle을 제공한다.

```ts
interface PiPlatformExtension {
  initialize?(ctx: ExtensionContext): Promise<void>;

  beforeAgentStart?(event: AgentStartEvent): Promise<void>;
  beforeTurn?(event: TurnEvent): Promise<void>;

  beforeModelRequest?(
    event: ModelRequestEvent,
  ): Promise<ModelRequestPatch | void>;

  afterModelResponse?(
    event: ModelResponseEvent,
  ): Promise<ModelResponsePatch | void>;

  beforeToolCall?(
    event: ToolCallEvent,
  ): Promise<ToolCallPatch | void>;

  afterToolCall?(
    event: ToolResultEvent,
  ): Promise<ToolResultPatch | void>;

  afterTurn?(event: TurnCompletedEvent): Promise<void>;

  /** Optional cold-start optimization only. Not durable authority. */
  snapshot?(): Promise<SerializableState | void>;

  /** Best-effort only. Must not be required for correctness. */
  shutdown?(): Promise<void>;
}
```

### 11.2 Lifecycle replay contract

Extension은 다음 실행 semantics를 MUST 받아들여야 한다.

- `initialize()`는 같은 session/runtime revision에서 여러 번 실행될 수 있다.
- Worker crash/eviction 후 hook은 durable settlement 이전이라면 다시 실행될 수 있다.
- `shutdown()`은 crash, OOM, kill에서 호출되지 않을 수 있다.
- correctness에 필요한 state는 ExtensionState API에 저장해야 한다.
- hook 내부에서 직접 외부 side effect를 수행해서는 안 된다.
- 외부 side effect가 필요하면 broker/tool effect protocol을 사용해야 한다.

### 11.3 Hook graph와 순서

Hook 순서는 다음 순서로 결정한다.

1. manifest의 `priority`
2. extension ID 오름차순
3. registration index

동일 Agent Bundle과 Runtime Revision은 항상 같은 hook 순서를 가져야 한다. initialization 완료 후 hook registry는 freeze해야 한다.

### 11.4 Hook patch 합성

여러 extension이 동일 event를 patch할 때 다음 pipeline을 사용한다.

```text
platform pre-policy
      ↓
ordered extension transforms
      ↓
structural validation
      ↓
platform post-policy / clamp
      ↓
Broker authorization
```

규칙:

- 각 patch는 이전 결과를 입력으로 순서대로 적용한다.
- 같은 scalar field는 기본적으로 deterministic last-writer-wins다.
- `sessionId`, `workspaceId`, `turnId`, authority, backend identity 등 security field는 extension patch 대상이 아니다.
- tool 이름/arguments가 변경되면 변경된 최종 값에 대해 permission을 다시 검사한다.
- extension이 network/resource/security policy를 완화할 수 없어야 한다.
- manifest는 patch 가능한 field를 hook type별로 제한할 수 있다.

### 11.5 Extension 간 간섭

같은 session에 로드된 extension들은 하나의 trust bundle로 취급한다.

악성 extension은 같은 세션 안에서 다음을 할 수 있다고 가정한다.

- prompt 변경
- tool call 변경
- 다른 extension hook 방해
- 응답 조작

하지만 다음은 할 수 없어야 한다.

- 다른 session의 Pi state 접근
- 다른 tenant의 workspace 접근
- current TurnAuthority 없이 broker 호출
- capability 없이 native process 실행
- 허가되지 않은 MCP 호출
- 허가되지 않은 network egress
- 플랫폼 secret 원문 열람

### 11.6 Hook 실패 정책

| 상황 | 처리 |
|---|---|
| extension 초기화 실패 | candidate Worker/session 시작 실패 |
| hook timeout | 현재 turn 실패 또는 manifest가 허용한 optional hook만 skip |
| hook 예외 | 현재 turn 실패 |
| optional telemetry hook 실패 | 로그 후 계속 |
| `snapshot()` 실패 | 경고 후 clean reconstruction 가능; runtime activation 자체를 영구 차단하지 않음 |
| `shutdown()` 실패/미실행 | 강제 종료 가능; correctness에 영향 없어야 함 |
| tool 이름 충돌 | Runtime Revision 생성 실패 |
| persistent state migration 실패 | candidate revision activation 중단, old revision 유지 |

### 11.7 Persistent state migration

`snapshot()`과 schema migration을 혼동해서는 안 된다.

```text
ExtensionState namespace
=
tenant / scope / extensionId / schemaVersion / stateGeneration
```

Runtime Revision 변경 중 schema가 바뀌면 copy-on-write migration을 수행한다. migration이 성공한 후에만 candidate Runtime Revision을 activate한다.

Migration 경로 규칙:

- `migrationsFrom`에 현재 schemaVersion으로의 직접 migration이 있으면 그것을 사용한다.
- 직접 경로가 없고 인접 버전 migration들이 모두 선언되어 있으면 순차 체인(v1→v2→v3)을 copy-on-write로 적용할 수 있다.
- 체인이 불완전하면 candidate activation은 실패하고 old revision을 유지한다.

## 12. Runtime Revision

Extension 선택, 설정, workerd compatibility, Pi adapter ABI가 변경되어도 실행 중 Worker를 직접 수정하지 않는다.

### 12.1 Runtime Revision 내용

Runtime Revision은 불변이며 최소 다음 정보를 포함한다.

```yaml
runtimeRevision:
  id: rev_00043
  digest: sha256:...

  workerd:
    binaryDigest: sha256:...
    compatibilityDate: "2026-08-01"
    compatibilityFlags: []
    loaderAbiVersion: 1

  pi:
    packageDigest: sha256:...
    adapterAbiVersion: 1
    agentEngine: low-level

  agentBundleDigest: sha256:...

  extensions:
    - id: official/pdf
      version: 1.4.2
      digest: sha256:...

  configurationDigest: sha256:...
  executionEnvironmentRequirementDigest: sha256:...
  policyGeneration: 17
```

Worker Loader cache identity는 `id`가 아니라 digest/ABI/compatibility를 포함한 runtime identity digest에서 계산한다.

### 12.2 Runtime Pointer

Session DO는 다음 pointer를 가진다.

```ts
interface RuntimePointer {
  activeRevision: string;
  candidateRevision?: string;
  previousRevision?: string;
  switchGeneration: number;
}
```

### 12.3 Staged activation

교체 절차:

```text
1. 새 설정 검증
2. extension dependency와 native package requirements resolve
3. 새 Agent Bundle 생성
4. Runtime Revision digest 계산
5. candidate extension-state namespace/migration 준비
6. candidate revision 기록
7. candidate Worker를 제한된 staging authority로 생성
8. initialization + read-only health check
9. 현재 active turn 종료 대기
10. Session DO switch lease 획득
11. CAS(activeRevision = old → candidate, switchGeneration++)
12. 새 turn admission을 candidate로 전환
13. old Worker drain
14. previousRevision을 rollback window 동안 유지
15. 기간 종료 후 old ephemeral resources 제거
```

health check용 authority는 workspace write, native side effect, external message send와 같은 mutation을 허용해서는 안 된다.

### 12.4 Rollback

candidate activation 이후 초기 turn에서 치명적 runtime incompatibility가 감지되면 정책에 따라 previous revision으로 CAS rollback할 수 있다.

이미 외부 side effect가 발생한 turn 자체를 rollback해서는 안 된다. Runtime rollback은 **다음 turn의 runtime 선택**만 변경한다.

## 13. Extension Manifest

Extension manifest는 extension의 **요청과 기능 요구사항**을 표현한다. 신뢰 여부나 review 결과는 manifest 자체가 주장하지 않고 Registry의 signed assessment가 결정한다.

```yaml
apiVersion: pi.platform/v1alpha2
kind: Extension

metadata:
  id: official/pdf
  version: 1.4.2
  publisher: platform
  digest: sha256:0123456789abcdef...

runtime:
  compatibility: pi-server
  entry: dist/index.mjs
  piApiVersion: v1
  priority: 100

configuration:
  schema: schemas/config.schema.json
  defaults:
    outputFormat: pdf

hooks:
  - beforeAgentStart
  - beforeToolCall
  - afterToolCall

tools:
  - name: pdf.render
    inputSchema: schemas/render.input.json
    outputSchema: schemas/render.output.json
    replay:
      mode: idempotency-key

permissions:
  workspace:
    read: true
    write: true

  execution:
    required: true
    commands:
      - pandoc
      - libreoffice
    packages:
      - id: document-tools
        version: ">=3.2.0 <4.0.0"

  network:
    mode: none

  mcp:
    servers: []

  secrets: []

state:
  scope: workspace
  schemaVersion: 3
  migrationsFrom: [2]

execution:
  supportedBackends:
    - nsjail
    - docker
    - firecracker

security:
  requestedMinimumAgentIsolation:
    processScope: shared
    outerIsolation: none
```

### 13.1 Tool replay declaration

외부 effect를 일으킬 수 있는 tool은 replay mode를 MUST 선언한다.

```yaml
replay:
  mode: safe              # 재실행 안전
```

또는:

```yaml
replay:
  mode: idempotency-key   # invocationId를 외부 시스템이 dedup
```

```yaml
replay:
  mode: confirm           # uncertain recovery 시 사용자 확인 필요
```

```yaml
replay:
  mode: never             # uncertain recovery 시 재실행 금지
```

`safe`는 read/query처럼 동일 호출을 반복해도 side effect가 없는 경우에만 허용한다.

### 13.2 Registry Security Assessment

Registry가 별도 signed record를 저장한다.

```yaml
registryAssessment:
  extensionDigest: sha256:...
  trustClass: platform-reviewed
  assessedAt: "2026-08-22T00:00:00Z"
  assessorKeyId: platform-security-1

  minimumAgentIsolation:
    processScope: shared
    outerIsolation: none

  allowedExecutionBackends:
    - nsjail
    - docker
    - firecracker
```

최종 최소 격리는 manifest 요청과 Registry assessment와 관리자 policy의 **가장 강한 요구**를 사용한다.

### 13.3 Manifest 검증

설치 시 다음을 검증해야 한다.

- extension ID와 version 형식
- digest 일치
- hermetic module graph
- 허용되지 않은 import와 dynamic import
- Node builtin 사용
- native addon 사용
- JSON Schema 유효성
- 중복 tool 이름
- tool replay declaration
- 지원 backend
- native package requirement satisfiability
- 요구 capability
- dependency cycle
- bundle 서명
- Registry security assessment 서명
- 최대 bundle 크기

## 14. Extension 설치와 선택

### 14.1 Offline Registry

오프라인 Extension Registry는 다음 정보를 저장한다.

```text
Extension Registry
├── metadata
├── immutable bundles
├── signatures
├── SBOM
├── configuration schemas
├── native package requirements
├── signed security assessments
├── compatibility information
└── environment-resolution metadata
```

### 14.2 Bundle installation pipeline

```text
extension package
   │
   ├── signature verify
   ├── digest verify
   ├── dependency lock verify
   ├── module graph compile
   ├── forbidden API scan
   ├── deterministic bundle
   ├── SBOM registration
   └── security assessment lookup
        │
        ▼
immutable installed extension revision
```

운영 중 session 생성 시 npm/PyPI/internet resolution을 수행해서는 안 된다.

### 14.3 사용자 설정

```yaml
userDefaults:
  extensions:
    - id: official/pdf
      version: 1.4.2

    - id: company/internal-tools
      version: 3.1.0

  extensionConfig:
    official/pdf:
      outputFormat: pdf
```

Session 생성 시 사용자 설정을 그대로 참조하지 않고 snapshot하여 Runtime Revision에 포함한다.

```text
User configuration
       │
       ▼
Session Runtime Revision
       │
       └── immutable snapshot
```

따라서 사용자의 기본 설정을 변경해도 이미 진행 중인 session은 자동으로 변경되지 않는다.

### 14.4 Native requirement resolution

선택된 모든 extension의 `permissions.execution.packages`를 합쳐 하나의 `ExecutionEnvironmentRevision`을 resolve한다.

```text
Extension A: python-runtime >=3.13
Extension B: document-tools 3.x
Extension C: ffmpeg 8.x
                 │
                 ▼
Execution Environment Resolver
                 │
                 ▼
env_standard_2026_08 / sha256:...
```

요구사항이 충돌하거나 허용된 prebuilt environment가 없으면 Runtime Revision 생성 단계에서 실패한다.

초기 버전은 동적 image composition 대신 curated prebuilt environment를 사용한다.

```text
minimal-v1
python-v1
document-tools-v1
browser-v1
full-standard-v1
```

## 15. celld State Plane

celld는 신뢰된 플랫폼 state code만 실행한다.

```text
celld
├── User DO
├── Session DO
├── Workspace DO
├── ExtensionState DO
├── CapabilityGeneration DO
└── Audit DO
```

celld는 사용자 extension이나 Pi를 실행하는 hostile-code sandbox로 사용하지 않는다. celld의 object-store credential과 internal/operator interface는 admin 권한으로 취급한다.

### 15.1 User DO

```ts
interface UserState {
  userId: string;
  tenantId: string;

  defaultExtensions: ExtensionSelection[];
  defaultExecutionBackend: "nsjail" | "docker" | "firecracker";
  preferredAgentIsolation?: AgentIsolationPolicy;

  modelConfiguration: ModelConfiguration;
  mcpConfiguration: McpConfigurationRef[];

  quotaProfile: string;
  revision: number;
}
```

### 15.2 Session DO — 단일 durable state machine

Session DO는 conversation, turn, effect, runtime pointer의 권위 있는 상태를 보유한다.

```ts
interface SessionState {
  sessionId: string;
  tenantId: string;
  userId: string;
  workspaceId: string;

  runtime: RuntimePointer;
  executionBackend: "nsjail" | "docker" | "firecracker";
  executionEnvironmentRevision: string;
  agentIsolation: AgentIsolationPolicy;

  status:
    | "created"
    | "starting"
    | "ready"
    | "running"
    | "interrupted"
    | "failed"
    | "closed";

  eventSequence: number;
  activeTurn?: TurnState;
  latestSettledTurn?: string;

  placementGeneration: number;
  policyGeneration: number;
}
```

Session DO 책임:

- 순차적인 turn admission
- active turn lease/fencing
- conversation entry/event 저장
- turn durable program counter
- effect prepare/settlement
- runtime pointer와 switch generation
- abort 상태
- agentd placement generation
- API idempotency record
- SSE durable event cursor

### 15.3 Turn State

```ts
interface TurnState {
  turnId: string;
  sequence: number;
  state:
    | "accepted"
    | "model_prepared"
    | "model_inflight"
    | "model_settled"
    | "tool_prepared"
    | "tool_inflight"
    | "tool_externally_committed"
    | "checkpointed"
    | "completed"
    | "failed"
    | "needs_confirmation";

  lease: TurnLease;
  activeEffectId?: string;
  checkpoint: AgentCheckpoint;
}
```

TurnState 불변식:

- `activeEffectId`는 최대 하나다. 하나의 turn에서 external effect는 한 시점에 최대 하나만 `prepared`와 `settled` 사이 상태에 있을 수 있다(순차 effect 불변식).
- model 응답이 복수 tool call을 포함하면 §9.2.3의 규칙으로 직렬화하며, 대기 목록은 checkpoint에 durable하게 저장된다.
- 병렬 effect가 필요해지는 경우 이 불변식과 §18의 write lease 모델을 함께 개정해야 한다.

### 15.4 Effect Record

모델 호출, native tool, Workspace mutation, MCP side effect는 모두 동일한 durable effect model을 사용한다.

```ts
interface EffectRecord {
  effectId: string;
  invocationId: string;
  turnId: string;

  service:
    | "model"
    | "workspace"
    | "executor"
    | "mcp"
    | "artifact"
    | "external-tool";

  operation: string;

  state:
    | "prepared"
    | "dispatched"
    | "externally_committed"
    | "settled"
    | "unknown"
    | "needs_confirmation";

  replayPolicy: "safe" | "idempotency-key" | "never" | "confirm";
  requestDigest: string;

  resultRef?: string;
  externalCommitId?: string;
  providerRequestId?: string;

  turnLeaseGeneration: number;
  placementGeneration: number;
}
```

Session DO transaction과 외부 서비스 transaction은 하나의 distributed transaction으로 가정하지 않는다. 복구는 effect state와 외부 invocation ledger를 조회하여 명시적으로 수행한다.

### 15.5 Workspace DO

Workspace DO는 authoritative VFS metadata와 revision state를 가진다.

```text
Workspace DO
├── directory/file metadata
├── blob digest references
├── revisions / root tree digest
├── mutation journal
├── active write lease
├── invocation ledger
├── snapshots
└── ACL / quota metadata
```

큰 file content는 Workspace DO SQLite에 직접 저장하지 않고 content-addressed Workspace Blob Store에 저장한다.

### 15.6 ExtensionState DO

```text
ExtensionState key
=
tenant / scope / extensionId / schemaVersion / stateGeneration
```

지원 scope:

- `user`
- `workspace`
- `session`

Extension JavaScript 전역 변수는 ephemeral state다. 재시작 후 유지해야 하는 값만 ExtensionState API를 통해 저장한다.

### 15.7 ACL과 quota

최소 role:

- `platform-admin`
- `tenant-admin`
- `workspace-owner`
- `workspace-member`
- `user`

모든 resource lookup은 object ID만으로 권한이 성립하지 않는다. tenant membership과 ACL을 검증해야 한다.

Quota는 최소 다음 단위로 설정 가능해야 한다.

- session 수
- workspace/blob 용량
- artifact 용량
- active sandbox 수
- CPU/memory resource profile
- model token/cost budget

### 15.8 celld 요구 보장 계약

본 스펙의 durable correctness는 celld가 다음을 보장한다는 전제 위에 있다. 이 계약은 celld upgrade마다 conformance로 재검증해야 하며(§A.4), 충족되지 않으면 state plane을 시작해서는 안 된다.

MUST:

- **object당 단일 writer.** 하나의 DO instance만 해당 object storage에 쓸 수 있고, 소유권 이전 후 이전 instance의 늦은 write는 거부된다.
- **transaction 원자성과 내구성.** storage transaction commit이 성공으로 응답되면 그 내용은 process crash/재시작 이후에도 관찰되어야 한다. commit 응답 전에 local durability(fsync 또는 동등 보장)가 성립해야 한다.
- **commit-before-dispatch 순서.** 플랫폼 코드가 commit 완료를 명시적으로 확인한 뒤에만 외부 dispatch를 진행할 수 있어야 한다. write coalescing/지연 flush를 사용하는 runtime은 명시적 durability barrier API를 제공해야 한다.
- **read-your-writes.** 동일 object의 후속 read는 이전 commit을 관찰한다.

Object store 복제(해당 구성에서):

- celld local durable state와 object store 복제본 사이 RPO 상한을 설정할 수 있어야 하며, reference 기본값은 5분 이하로 한다.
- host local disk 유실 시 object store 복제본으로 복구하고, 복구 지점 이후의 turn/effect는 §49 recovery protocol로 정리한다. uncertain effect는 replay policy를 따른다.
- 복구 지점 손실 가능 구간이 존재했음을 audit에 기록한다.

백업 목표:

- reference deployment는 백업 RPO ≤ 24h(기본 daily), 복구 리허설 기준 RTO ≤ 4h를 목표로 하며, 값은 설정으로 조정한다(Phase 2 backup/restore drill로 검증).
- 백업은 celld state와 object store를 GC grace를 고려한 일관 절차로 캡처한다. `workspaceBlobGcGrace`는 백업 주기 이상이어야 한다.

## 16. Object Store

celld state, workspace blob, artifact, immutable bundle은 validated object store에 저장한다.

```text
Object Store
├── pi-celld-state
├── pi-workspace-blobs
├── pi-artifacts
├── pi-extension-bundles
├── pi-runtime-bundles
├── pi-execution-environments
└── pi-backups
```

reference air-gap bundle은 release마다 라이선스와 운영 특성을 검증한 특정 object store 구현 하나를 pin하여 포함한다. 플랫폼 계약은 구현 이름이 아니라 §16.1의 CAS conformance이며, 이를 통과하는 다른 S3-호환 구현으로 교체할 수 있다.

### 16.1 Celld bucket 요구사항

celld용 object store는 단순한 S3 API 지원만으로 충분하지 않다. conditional write와 ETag 기반 compare-and-swap 동작을 실제 end-to-end test로 검증해야 한다.

설치 시 MUST 수행:

```text
1. object 생성
2. ETag 획득
3. 올바른 If-Match 조건부 갱신
4. 잘못된 ETag 갱신 실패 확인
5. If-None-Match 충돌 확인
6. read-after-write 확인
7. concurrent CAS winner가 하나인지 확인
8. restart 이후 지속성 확인
```

이 테스트를 통과하지 못하면 celld를 시작해서는 안 된다.

### 16.2 Workspace Blob Store

Workspace file content는 content-addressed object로 저장한다.

```text
sha256(file bytes)
       │
       ▼
pi-workspace-blobs/sha256/ab/cd/...
```

Workspace DO revision은 path와 metadata, blob digest를 참조한다. 동일한 content는 tenant 정책이 허용하는 범위에서 deduplicate할 수 있다.

cross-tenant deduplication은 side-channel과 삭제 semantics를 복잡하게 하므로 reference deployment에서는 tenant scope dedup을 권장한다.

### 16.3 Immutable bundle store

다음 artifact는 digest로 주소화하고 overwrite하지 않는다.

- extension bundle
- Pi runtime bundle
- Execution Environment rootfs/image metadata
- Firecracker kernel/rootfs
- seccomp profile
- SBOM

logical tag는 immutable digest를 가리키는 signed metadata일 뿐이다.

### 16.4 Garbage Collection

GC는 단순한 reference count에만 의존하지 않고 mark-and-sweep를 지원해야 한다.

mark root:

- active/previous Runtime Revision
- Workspace current revision과 retained snapshot
- live artifact reference
- installed Extension Revision
- installed Execution Environment Revision
- backup retention set

sweep 대상:

- unreferenced workspace blob
- expired artifact
- abandoned runtime bundle
- old environment rootfs/image
- orphan sandbox snapshot
- incomplete multipart upload

GC는 active revision이나 in-flight workspace commit이 참조하는 object를 삭제해서는 안 된다.

GC 실행 규칙:

- GC는 stop-the-world 없이 동작해야 한다. mark는 DO별 root set export(snapshot/cursor 기반의 일관 열거)를 수집해 수행한다.
- enumeration 중 새로 생성된 참조는 생성 시각 기반 grace(최소 `workspaceBlobGcGrace`)로 sweep에서 보호한다.
- 대규모 tenant에서는 mark를 tenant/파티션 단위 증분으로 수행할 수 있다.

## 17. Workspace Subsystem

### 17.1 기본 구조

Cloudflare Computer의 핵심 아이디어인 **durable authoritative filesystem + disposable execution projection**을 채택하되, upstream computerd를 core runtime dependency로 두지 않는다.

```text
Pi Worker
    │
    ▼
Workspace Broker
    │
    ├────────── direct file RPC ──────────┐
    │                                      │
    ▼                                      ▼
Workspace DO                         Workspace Blob Store
    │
    │ snapshot / delta / commit
    ▼
ExecutionProvider
    │
    ▼
Sandbox
└── sandboxd
    └── /workspace materialization
```

### 17.2 `sandboxd`

`sandboxd`는 Docker/Firecracker/NsJail에서 동일한 Go binary를 사용한다.

책임:

- one-time sandbox handshake
- sandbox identity를 command payload가 아니라 launch-time authority에서 고정
- workspace snapshot materialization
- process spawn / stdin / stdout / stderr / signal / wait
- process group kill
- final filesystem manifest 생성
- resource usage reporting
- workspace commit acknowledgment relay
- health reporting

`sandboxd`는 tenantId/workspaceId를 client가 임의 문자열로 지정하도록 하는 API를 제공해서는 안 된다.

통신:

| Backend | Control channel |
|---|---|
| NsJail | private Unix domain socket bind mount |
| Docker | private Unix domain socket bind mount |
| Firecracker | vsock |

### 17.3 Upstream computerd 정책

upstream `computerd`/FUSE integration은 향후 optional `WorkspaceProjectionProvider` 구현으로 실험할 수 있다. v0.3 core correctness는 `sandboxd + materialized manifest`만으로 성립해야 한다.

따라서 다음은 core non-goal이다.

- upstream computerd RPC protocol에 platform architecture를 고정
- FUSE가 없으면 workspace가 동작하지 않는 구조
- sandbox local VFS를 authoritative state로 취급

### 17.4 Workspace Tree Model

```ts
interface WorkspaceTreeEntry {
  path: string;
  type: "file" | "directory" | "symlink";
  mode: number;

  size?: number;
  contentDigest?: string;
  symlinkTarget?: string;
}

interface WorkspaceSnapshot {
  workspaceId: string;
  revision: number;
  rootDigest: string;
  entries: WorkspaceTreeEntry[];
}
```

MVP filesystem subset:

- regular file
- directory
- safe relative symlink
- executable bit

기본적으로 금지:

- device node
- FIFO
- Unix socket를 durable workspace entry로 commit
- absolute symlink
- workspace 밖으로 탈출하는 relative symlink
- hard link semantic 보존

hard link는 거부하거나 일반 file copy로 canonicalize한다.

UID/GID는 canonical sandbox user로 normalize한다.

Manifest 표현:

- 소규모 워크스페이스는 flat `entries` snapshot을 사용할 수 있다.
- entry 수가 `treeManifestThreshold`(reference 기본 50,000)를 넘는 워크스페이스는 git과 유사한 **directory 단위 content-addressed tree object**로 저장해야 한다. 각 tree object는 자식 entry와 자식 tree digest를 참조하고 revision은 root tree digest만 가리킨다. 이 표현은 subtree 단위 부분 diff/부분 materialize를 가능하게 하고 DO storage 항목 크기 한계를 회피한다.

Path 규칙(MUST):

- path는 UTF-8이며 canonical form은 NFC다. 정규화 후 충돌하는 두 entry는 거부한다.
- workspace filesystem semantics는 case-sensitive를 canonical로 한다.
- path 구성요소는 255 bytes, 전체 path는 4096 bytes를 상한으로 한다.
- `.`/`..`/빈 구성요소를 포함한 path는 거부한다.
- entry 수와 metadata 총량은 workspace quota(§15.7)에 포함한다.

### 17.5 `materialized-manifest` projection

기본 projection mode다.

```text
Workspace DO
     │ snapshot + required blobs
     ▼
sandbox local /workspace
     │ command/process mutations
     ▼
post-exec filesystem scan
     │
     ▼
canonical mutation set
     │
     ▼
Workspace DO commit
```

Correctness는 inotify/fanotify event에만 의존해서는 안 된다. 초기 구현은 실행 전/후 canonical manifest 비교를 authoritative diff로 사용한다.

watcher는 성능 최적화 hint로 MAY 사용한다.

가속 diff 경로:

```yaml
workspace:
  diffStrategy: auto   # auto | full-scan | overlayfs
```

- `full-scan`은 언제나 correctness reference다.
- materialization이 read-only lower(고정 snapshot tree) + invocation/sandbox 전용 overlayfs upper로 구성되는 경우(NsJail/Docker의 host-prepared tree, §17.8), `overlayfs` 모드는 **upperdir 내용과 whiteout을 canonical mutation set으로 사용할 수 있다**. rename은 delete+create로 canonicalize된다(full-scan diff와 동일한 semantics).
- `auto`는 위 조건을 충족하면 overlayfs, 아니면 full-scan을 선택한다.
- overlayfs 모드에서도 주기적/표본 full-scan 대조 검증을 SHOULD 수행하고 불일치는 sandbox violation event로 기록한다.
- mtime/size 기반 manifest cache는 어느 모드에서든 hint일 뿐 authority가 아니다.

### 17.6 Large file handling

대형 file은 Workspace DO request body에 전체 bytes를 반복 전달하지 않는다.

```text
sandboxd
  └── hash + upload blob
          │
          ▼
Workspace Blob Store
          │ digest
          ▼
Workspace DO commit metadata
```

upload capability는 해당 workspace/invocation에만 유효해야 하며 arbitrary object key를 지정할 수 없어야 한다.

Quota 정산:

- upload capability 발급 시 예상 크기를 workspace quota에서 reservation하고, commit 시 실제 크기로 정산한다.
- commit되지 않은 upload는 reservation 만료 시 해제하고 object는 GC grace 이후 수거한다(§49.10).

### 17.7 Experimental FUSE mode

FUSE는 고급 실험 모드로 MAY 제공한다.

```yaml
workspace:
  projectionMode: fuse-experimental
```

기본값:

```yaml
workspace:
  projectionMode: materialized-manifest
```

### 17.8 Backend별 materialization 전송

Materialization의 correctness 계약은 backend와 무관하지만 전송 메커니즘은 backend별로 다르고 성능을 좌우하므로 reference 구현을 명시한다.

공통(MUST):

- compute node는 digest 검증된 node-local blob cache를 유지한다. cache 공유 범위는 §16.2의 dedup 정책을 따른다.
- sandbox에 노출되는 tree는 sandbox 전용으로 준비한다. 공유 blob cache directory를 sandbox 안에 직접 mount하지 않는다.
- blob cache에서 hardlink/reflink로 sandbox tree를 구성할 수 있으나, 이 경우 lower는 read-only로 mount하고 모든 쓰기를 upper/scratch로 격리하여 cache 오염을 방지한다.

| Backend | Reference 전송 |
|---|---|
| NsJail | host가 준비한 snapshot tree를 read-only bind + overlay upper(또는 rw materialized dir) |
| Docker | 동일한 host-prepared tree를 bind/volume mount |
| Firecracker | host가 snapshot tree로부터 빌드한 ext4(또는 read-only erofs + writable upper) 이미지를 virtio-blk로 attach; 소규모 워크스페이스/증분 갱신은 vsock streaming을 MAY 사용 |

- Firecracker 경로의 이미지 빌드 비용은 blob cache와 이전 revision 이미지의 delta 재사용으로 완화한다.
- 전송 방식과 무관하게 commit semantics(§18.2)와 mutation set 산출 규칙(§17.5)은 동일해야 한다.

## 18. Workspace 동시성

하나의 workspace에 여러 session이 연결될 수 있지만 mutable native execution은 기본적으로 workspace당 하나의 write lease만 가진다.

```text
Session A ─┐
Session B ─┼── Workspace W
Session C ─┘
```

### 18.1 Workspace write lease

```ts
interface WorkspaceWriteLease {
  leaseId: string;
  sandboxId: string;
  backend: "nsjail" | "docker" | "firecracker";
  baseRevision: number;
  generation: number;
  expiresAt: number;
}
```

규칙:

- file read는 병렬 허용
- direct file RPC write는 revision 기반 optimistic concurrency
- native command가 workspace를 변경하는 동안 sandbox가 write lease 소유
- lease 동안 외부 direct write는 대기 또는 conflict
- stale generation의 commit은 거부
- write conflict 자동 overwrite 금지

Lease 획득 대기 정책:

```yaml
workspace:
  leaseWaitPolicy: queue    # queue | fail
  leaseAcquireTimeout: 120s
```

- 대기 중 effect는 `prepared` 상태를 유지하고 client에는 ephemeral `tool.lease.waiting` 이벤트를 전달한다.
- timeout 시 effect는 실패로 settle하며, 응답에는 현재 lease 보유 session 식별 정보를 포함할 수 있다(ACL 범위 내).

### 18.2 Native mutation flow

```text
1. Session DO: effect(prepared) 기록
2. Workspace DO: write lease 획득 + base revision 고정
3. sandbox에 snapshot/delta materialize
4. Session DO: effect(dispatched)
5. command/process 실행
6. sandboxd가 post-exec manifest 생성
7. mutation set + blob upload 준비
8. Workspace DO commit(invocationId, requestDigest, baseRevision, generation)
9. Workspace DO가 새 revision + invocation ledger를 하나의 transaction으로 기록
10. workspaceCommitId 반환
11. Session DO: effect(externally_committed → settled)
12. write lease release
13. Pi에 tool result 제공
```

### 18.3 Invocation Ledger

Workspace DO는 mutation commit을 invocation ID로 deduplicate한다.

```ts
interface WorkspaceInvocationRecord {
  invocationId: string;
  requestDigest: string;
  baseRevision: number;

  status: "committed" | "rejected";
  result?: {
    workspaceCommitId: string;
    revision: number;
    rootDigest: string;
  };
}
```

동일 `invocationId`로 재요청 시:

- `requestDigest` 동일 + committed → 기존 결과 반환
- `requestDigest` 다름 → corruption/security error
- 이전 요청이 commit되지 않았음 → 정상 validation 후 처리

### 18.4 Cross-DO crash recovery

다음 crash window는 정상 상태로 간주하고 복구 protocol을 정의한다.

```text
Workspace DO commit 성공
      │
      X SessionHost/agentd crash
      │
Session DO settlement 미기록
```

복구 시 Session DO의 active effect가 `dispatched` 또는 `unknown`이고 service가 workspace라면 Workspace DO invocation ledger를 조회한다.

- committed → `externally_committed`로 복구 후 settle
- 없음 → replay policy에 따라 재실행 가능
- 결과 불명/외부 system → `needs_confirmation` 가능

### 18.5 Sandbox cache와 workspace write authority

같은 workspace에 backend별 sandbox cache가 동시에 존재할 수 있다.

```text
Workspace W
├── cached NsJail sandbox
├── cached Docker sandbox
├── cached Firecracker sandbox
└── one global mutable write lease
```

cache 존재가 write authority를 의미하지 않는다.

### 18.6 Read-only invocation

workspace write 권한이 없는 tool/extension의 native 실행은 write lease를 획득하지 않는다.

- snapshot은 특정 revision으로 고정하여 materialize한다.
- `/workspace`는 read-only로 mount하며 sandboxd가 이를 enforce한다.
- post-exec manifest scan과 workspace commit을 생략한다.
- 산출물은 artifact API 또는 tool 결과 payload로만 반환한다.
- read-only invocation은 write lease 보유자와 병렬로 실행될 수 있다.

manifest의 `permissions.workspace.write: false`가 이 경로의 선언적 근거이며, write 권한이 있는 extension도 tool 단위로 read-only 실행을 요청할 수 있다.

## 19. Native Execution Backend

사용자는 native 실행 환경으로 다음 중 하나를 선택할 수 있다.

- `nsjail`
- `docker`
- `firecracker`

UI 권장 표시:

```text
실행 환경
○ NsJail       — Lightweight / host kernel 공유
○ Docker       — Container / host kernel 공유
○ Firecracker  — MicroVM / guest kernel
```

### 19.1 Backend 특성

| 항목 | NsJail | Docker | Firecracker |
|---|---|---|---|
| 시작 비용 | 매우 낮음 | 낮음~중간 | 중간 |
| daemon 필요 | 아니오 | Docker daemon | 아니오, executord가 VM process 관리 |
| package artifact | read-only rootfs tree | OCI image | kernel + rootfs |
| host kernel 공유 | 예 | 예 | guest workload와 직접 공유하지 않음 |
| seccomp | Kafel/seccomp-bpf | OCI seccomp | host jailer + guest 정책 |
| cgroup | 직접 사용 | Docker runtime 경유 | jailer/executord |
| 네트워크 | netns/veth | container netns | TAP/netns |
| 권장 용도 | curated short/medium native tool, 저지연 | 범용 toolchain, OCI 호환 | hostile/high-risk native code |

NsJail이 항상 Docker보다 안전하거나 항상 약하다고 가정하지 않는다. 둘 다 shared-kernel class이며 실제 보안 강도는 namespace, mount, UID mapping, seccomp, cgroup, network policy에 따라 달라진다.

### 19.2 선택 범위

사용자는 다음 범위에서 기본값을 지정할 수 있다.

1. server default
2. user default
3. workspace default
4. session override
5. tool-specific policy minimum

우선순위:

```text
tool/session explicit request
    >
workspace default
    >
user default
    >
server default
```

그 후 다음 교집합을 계산한다.

```text
requested backend
    ∩ server allowed backends
    ∩ Registry security policy
    ∩ extension supported backends
    ∩ resolved environment artifacts
    ∩ host available backends
```

교집합이 비어 있으면 실패한다.

### 19.3 Silent fallback 금지

기본적으로 backend를 조용히 변경하지 않는다.

```yaml
execution:
  fallback:
    mode: disabled
```

관리자가 fallback을 명시적으로 허용하면 응답과 audit에 requested/resolved backend를 모두 남겨야 한다. 보안 등급을 낮추는 fallback은 별도 policy opt-in이 필요하다.

### 19.4 Execution Environment Revision

여러 extension의 native package 요구사항을 하나의 immutable environment로 resolve한다.

```ts
interface ExecutionEnvironmentRevision {
  id: string;
  digest: string;
  architecture: "x86_64" | "aarch64";

  packages: Array<{
    id: string;
    version: string;
    digest: string;
  }>;

  sandboxdDigest: string;
  seccompProfileDigest: string;
  filesystemPolicyDigest: string;

  artifacts: {
    nsjail?: {
      rootfsDigest: string;
    };

    docker?: {
      imageDigest: string;
    };

    firecracker?: {
      kernelDigest: string;
      rootfsDigest: string;
    };
  };
}
```

동일 logical toolchain definition에서 backend artifact를 생성한다.

```text
Canonical environment definition
          │
          ├── rootfs tree ───────→ NsJailProvider
          ├── OCI image ─────────→ DockerProvider
          └── ext4 rootfs+kernel → FirecrackerProvider
```

### 19.5 Sandbox cache key

sandbox reuse 여부는 최소 다음 key에서 결정한다.

```text
tenantId
+ scope identity(workspace/session/invocation)
+ backend
+ executionEnvironmentDigest
+ resourceProfileDigest
+ networkPolicyDigest
+ secretExposureClass
+ sandboxProtocolVersion
```

backend를 workspace의 단일 mutable 속성으로 취급하지 않는다. Workspace default는 **향후 요청의 선택 기본값**일 뿐이다.

## 20. 공통 ExecutionProvider API

ExecutionProvider는 일회성 command뿐 아니라 stdio MCP와 향후 browser service처럼 장기 process를 다룰 수 있어야 한다.

```ts
interface ExecutionProvider {
  capabilities(): Promise<ExecutionCapabilities>;

  ensureSandbox(
    spec: SandboxSpec,
  ): Promise<SandboxHandle>;

  materialize(
    handle: SandboxHandle,
    snapshot: WorkspaceSnapshotRef,
  ): Promise<MaterializeResult>;

  spawn(
    handle: SandboxHandle,
    request: SpawnRequest,
  ): Promise<ProcessHandle>;

  attach(
    process: ProcessHandle,
  ): AsyncIterable<ProcessEvent>;

  writeStdin(
    process: ProcessHandle,
    data: Uint8Array,
  ): Promise<void>;

  closeStdin(
    process: ProcessHandle,
  ): Promise<void>;

  signal(
    process: ProcessHandle,
    signal: ProcessSignal,
  ): Promise<void>;

  wait(
    process: ProcessHandle,
  ): Promise<ProcessResult>;

  commitWorkspace(
    handle: SandboxHandle,
    request: WorkspaceCommitRequest,
  ): Promise<WorkspaceCommitResult>;

  stop(
    handle: SandboxHandle,
  ): Promise<void>;

  destroy(
    handle: SandboxHandle,
  ): Promise<void>;

  health(
    handle: SandboxHandle,
  ): Promise<SandboxHealth>;
}
```

편의 API로 `exec()`를 MAY 제공한다.

```text
exec = spawn → optional writeStdin → closeStdin → wait
```

### 20.1 SandboxSpec

```ts
interface SandboxSpec {
  launchAuthority: OpaqueSandboxAuthority;

  backend: "nsjail" | "docker" | "firecracker";
  executionEnvironmentDigest: string;

  resourceProfile: string;
  networkPolicy: NetworkPolicy;
  workspaceProjection: "materialized-manifest" | "fuse-experimental";

  scope: "workspace" | "session" | "invocation";

  idleTimeoutSeconds: number;
  maximumLifetimeSeconds: number;
}
```

extension이 `tenantId`, `workspaceId`, `sandboxId`, host path를 직접 지정하게 해서는 안 된다.

### 20.2 SpawnRequest

```ts
interface SpawnRequest {
  invocationId: string;

  executable: string;
  arguments: string[];
  workingDirectory: string;

  environmentHandles: SecretHandle[];

  timeoutSeconds: number;
  outputLimitBytes: number;

  stdinMode: "closed" | "stream";
}
```

`executable`은 manifest/environment allowlist에서 resolve해야 하며 arbitrary host path로 해석해서는 안 된다.

### 20.3 ProcessHandle

```ts
interface ProcessHandle {
  sandboxId: string;
  processId: string;
  invocationId: string;
  generation: number;
}
```

ProcessHandle은 opaque하다. caller가 OS PID를 권한 identity로 사용해서는 안 된다.

### 20.4 Process event

```ts
type ProcessEvent =
  | { type: "started" }
  | { type: "stdout"; data: Uint8Array }
  | { type: "stderr"; data: Uint8Array }
  | { type: "resource"; usage: ProcessUsage }
  | { type: "exit"; result: ProcessResult }
  | { type: "error"; code: string; message: string };
```

stdout/stderr는 backpressure와 output limit을 MUST 가진다.

### 20.5 Cancellation

cancel은 단일 PID kill이 아니라 sandboxd가 관리하는 process group/cgroup 전체를 종료해야 한다. timeout도 같은 경로를 사용한다.

### 20.6 Protocol versioning

`platformd ↔ executord ↔ sandboxd` protocol에는 다음을 포함한다.

- protocol version
- feature bitmap
- sandbox generation
- invocation ID
- request digest
- maximum frame size

서로 호환되지 않는 version은 fail-closed한다.

## 21. NsJailProvider

NsJail은 OCI container engine이 아니라 Linux process isolation tool이지만, 본 플랫폼에서는 `ExecutionProvider`를 구현하는 first-class lightweight backend로 취급한다.

NsJail은 Linux namespaces, cgroup, rlimit, seccomp-bpf/Kafel, chroot/pivot-root와 read-only/custom mount를 조합할 수 있으므로 curated native tool 실행에 적합하다. 단, host kernel을 공유하므로 Firecracker와 같은 VM 경계를 제공하지 않는다.

### 21.1 구조

```text
executord
    │
    ├── environment rootfs manager
    ├── UID/GID allocator
    ├── cgroup v2 controller
    ├── network namespace / nftables manager
    └── nsjail launcher
            │
            ▼
       NsJail sandbox
       ├── sandboxd (PID 1/supervisor)
       ├── read-only environment rootfs
       ├── /workspace
       ├── /scratch
       ├── tmpfs /tmp
       └── private control UDS
```

NsJail binary나 config를 extension/user가 직접 호출하거나 수정할 수 없어야 한다. `executord`만 launcher 권한을 가진다.

### 21.2 Rootfs model

NsJail은 Docker처럼 image lifecycle을 제공하지 않으므로 플랫폼이 rootfs를 관리한다.

```text
ExecutionEnvironmentRevision
        │
        └── nsjail.rootfsDigest
                │
                ▼
/var/lib/pi-platform/environments/<digest>/nsjail/rootfs
```

rootfs 요구사항:

- root 소유의 immutable directory/tree
- digest 검증 후 등록
- sandbox에서는 read-only bind/pivot-root
- 동일 rootfs를 여러 jail이 read-only 공유 가능
- system package manager write/install은 runtime 중 기본 금지
- mutable data는 `/workspace`, `/scratch`, `/tmp`, `/run` 등 명시된 mount에만 허용

동적 package 설치가 필요한 extension은 사전에 새로운 `ExecutionEnvironmentRevision`을 빌드해야 한다.

### 21.3 Namespace policy

reference production policy는 다음 namespace를 사용한다.

```text
USER   required
MOUNT  required
PID    required
IPC    required
UTS    required
NET    required
CGROUP recommended/host-managed cgroup v2
TIME   optional
```

`executord`가 host capability 검사 결과를 바탕으로 필요한 namespace를 생성할 수 없으면 해당 backend를 unavailable로 표시한다. production에서 보안 namespace를 조용히 비활성화해서 계속 실행해서는 안 된다.

### 21.4 UID/GID policy

sandbox process가 host root 권한으로 실행되어서는 안 된다.

권장 흐름:

```text
executord(root/capability-restricted launcher)
    │
    ├── sandbox 전용 host UID/GID 할당
    ├── user namespace mapping 설정
    └── nsjail 시작
           │
           ▼
inside uid 0 또는 sandbox uid
maps to unique unprivileged host uid/gid
```

- sandbox마다 고유한 host UID/GID를 할당하는 것을 SHOULD 한다.
- rootfs는 sandbox UID가 수정할 수 없어야 한다.
- Workspace projection은 해당 sandbox UID가 필요한 경로만 쓰게 한다.
- `setuid` binary를 허용하기 위해 `no_new_privs`를 끄는 설정을 사용해서는 안 된다.
- retained Linux capabilities는 기본 0개다.

### 21.5 Mount policy

기본 mount model:

```text
/                  environment rootfs, read-only
/workspace          workspace projection, rw only with lease
/scratch            ephemeral quota-controlled rw
/tmp                 tmpfs rw, size limited
/run                 tmpfs rw, minimal
/proc                minimal proc mount
/dev/null            explicit device
/dev/zero            explicit device
/dev/urandom         explicit device
```

다음 host path를 bind mount해서는 안 된다.

- `/var/run/docker.sock`
- `/run/containerd/*`
- `/dev/kvm`
- `/proc/sys` writable
- `/sys` writable
- host `/home`
- host `/root`
- platform data directory 전체
- object-store credential directory

mount source path는 user request에서 직접 받지 않고 environment/sandbox metadata에서 `executord`가 계산한다.

### 21.6 Seccomp policy

NsJail의 Kafel/seccomp-bpf를 사용한다.

정책 원칙:

- seccomp profile은 `ExecutionEnvironmentRevision`에 digest로 고정
- user/extension이 raw seccomp string을 제공하지 못함
- baseline은 privilege escalation, host introspection, kernel attack surface를 줄이는 방향으로 구성
- toolchain별 필요한 syscall 차이를 conformance test로 관리
- thread/process 생성이 필요한 runtime은 필요한 범위만 허용
- nested namespace creation, ptrace, arbitrary mount, kernel module, raw privileged operation 등은 기본 차단
- seccomp 위반은 structured sandbox violation event로 기록

가능한 environment에서는 allowlist 기반 profile을 권장하되, LibreOffice/Chromium처럼 syscall surface가 넓은 environment는 검증된 baseline deny policy를 사용할 수 있다.

### 21.7 Resource control

resource limit의 authority는 `executord`가 생성한 cgroup v2 subtree다. NsJail rlimit은 추가 방어선으로 사용한다.

적용 항목:

- CPU quota/weight
- memory.max
- memory.swap.max
- pids.max
- wall clock timeout
- RLIMIT_NOFILE
- RLIMIT_FSIZE
- optional RLIMIT_AS/CPU
- scratch disk quota

OOM/timeout/cancel 시 sandboxd process group과 cgroup 전체를 종료한다.

### 21.8 Network policy

기본값은 isolated NET namespace와 loopback만 허용하는 `none`이다.

```text
Host
├── executord
└── nsjail netns
    └── lo only
```

network를 허용할 경우 reference production 구현은 `executord`가 veth pair를 만들고 jail에 한쪽 interface를 전달하며 host nftables/proxy에서 egress를 제한한다.

```text
NsJail netns
    │ veth
    ▼
host policy namespace/bridge
    │ nftables + DNS/egress proxy
    ▼
allowed LAN destinations
```

NsJail의 userland networking(`pasta`)은 development/rootless 실험 모드로 MAY 지원한다. production allowlist를 `pasta` 자체에만 의존해서는 안 되며, 플랫폼 egress policy와 통합되지 않는 경우 비활성화한다.

### 21.9 sandboxd control channel

NsJail sandbox에는 private host directory 하나만 control socket용으로 bind mount한다.

```text
/run/pi-platform/sandboxes/<sandboxId>/
└── control.sock
```

규칙:

- directory는 `executord`만 생성
- random sandbox ID + generation 사용
- mode/ownership 제한
- sandboxd가 one-time handshake 완료 후 capability nonce 폐기
- 다른 sandbox socket directory를 mount하지 않음
- public TCP listener 사용 금지

### 21.10 Lifecycle

workspace/session scope에서는 하나의 NsJail instance 안에서 sandboxd를 장기 실행하여 여러 process를 spawn할 수 있다.

```text
ensureSandbox
  ↓
nsjail + sandboxd start
  ↓
materialize
  ↓
spawn / wait 반복
  ↓
idle timeout / lifetime
  ↓
destroy namespace + cgroup + scratch
```

`invocation` scope는 command마다 새 jail을 만들 수 있다.

### 21.11 제한사항

- host kernel 공유: kernel escape는 host compromise로 이어질 수 있음
- OCI image runtime이 아님: rootfs extraction/build/update를 플랫폼이 담당
- CRIU/process migration을 지원하지 않음
- Docker image에 의존하는 third-party tool을 그대로 실행하려면 별도 environment 변환이 필요
- privileged container semantics, nested Docker, host device passthrough는 지원하지 않음
- Firecracker가 요구되는 trust class를 NsJail로 낮출 수 없음

### 21.12 적합한 사용 사례

권장:

- Python/Node script
- compiler
- ffmpeg
- pandoc
- 일반 CLI
- stdio MCP
- 내부에서 검증한 document tool
- 짧고 빈번한 native command

조건부:

- LibreOffice
- Chromium/headless browser
- 복잡한 language runtime

이들은 더 넓은 seccomp/mount 정책과 shared-memory/device 요구가 있어 별도 curated environment와 conformance test가 필요하다.

비권장:

- 명시적으로 hostile한 arbitrary binary
- kernel exploit 연구 workload
- 강한 tenant boundary가 필수인 외부 사용자 코드

이 경우 Firecracker를 사용한다.

### 21.13 Provider availability test

`platformctl doctor`는 NsJail backend에 대해 최소 다음을 실제 실행해 검증한다.

```text
✓ USER/MOUNT/PID/IPC/UTS/NET namespace
✓ cgroup v2 resource limit
✓ no_new_privs 유지
✓ capability drop
✓ read-only rootfs
✓ workspace-only write
✓ seccomp denial
✓ host path invisibility
✓ network default deny
✓ timeout 시 process tree kill
✓ sandboxd UDS authentication
✓ sandbox destroy 후 namespace/cgroup/scratch cleanup
```

## 22. DockerProvider

### 22.1 구조

```text
executord
    │ Docker API
    ▼
Docker daemon
    │
    ▼
sandbox container
├── sandboxd
├── toolchain from ExecutionEnvironmentRevision
├── /workspace
├── read-only rootfs
└── writable scratch/tmpfs
```

Docker daemon socket은 `executord`만 접근할 수 있다.

```text
User code        X Docker socket
Pi Worker        X Docker socket
Extension        X Docker socket
platformd        X Docker socket
sandboxd         X Docker socket
executord        ✓ Docker socket
```

### 22.2 Image resolution

Docker image는 Extension manifest가 직접 지정하지 않는다.

```text
ExecutionEnvironmentRevision
        │
        └── artifacts.docker.imageDigest
                │
                ▼
DockerProvider
```

실행 시 tag가 아니라 immutable digest를 사용한다.

### 22.3 기본 보안 설정

모든 sandbox container에 다음을 적용한다.

```text
non-root user
read-only root filesystem
tmpfs /tmp and /run
cap-drop ALL
no-new-privileges
pinned seccomp profile
PID limit
CPU limit
memory + swap limit
scratch disk quota
timeout
network disabled by default
Docker socket unmounted
host namespace sharing disabled
privileged=false
host devices none by default
```

Docker의 default seccomp만으로 extension-specific policy가 완성되었다고 가정하지 않는다. environment conformance에서 필요한 syscall을 검증하고 platform seccomp profile digest를 고정한다.

### 22.4 `sandboxd`

container entrypoint는 reference implementation에서 `sandboxd`다.

```text
container PID 1: sandboxd
      │
      ├── spawn process
      ├── process group/cgroup tracking
      ├── workspace manifest
      └── private UDS
```

control channel은 host의 sandbox별 private Unix domain socket directory를 mount하여 사용한다. public TCP listener를 기본으로 사용하지 않는다.

### 22.5 Rootless Docker

Rootless Docker는 선택 기능으로 제공한다. cgroup v2와 systemd delegation 조건을 doctor에서 확인한다.

```yaml
executors:
  docker:
    mode: rootless
    socket: unix:///run/user/1001/docker.sock
```

Reference full profile에서는 system Docker를 허용하되, 사용자 코드가 daemon socket에 도달할 경로를 만들지 않는다.

### 22.6 보안 분류

Docker는 Firecracker와 달리 host kernel을 공유한다. hostile workload가 kernel escape risk를 수용할 수 없는 경우 정책은 Firecracker를 요구해야 한다.

## 23. FirecrackerProvider

### 23.1 구조

```text
executord
    │
    ├── firecracker API socket
    ├── jailer
    ├── cgroup v2
    ├── network namespace
    └── TAP / nftables
          │
          ▼
Firecracker microVM
├── pinned Linux kernel
├── read-only base rootfs
├── writable scratch disk
├── sandboxd
├── vsock control channel
└── optional network interface
```

Firecracker는 Linux x86_64/aarch64 호스트와 KVM을 요구한다. production 격리에서는 jailer, cgroup, namespace, privilege dropping을 함께 사용한다.

### 23.2 필수 정책

- Firecracker와 jailer version/digest 동일 release set
- 검증된 pinned binary 사용
- microVM마다 고유 UID/GID
- microVM별 cgroup
- API socket은 executord 전용 private path
- jail root path를 user input으로 받지 않음
- read-only kernel/base rootfs
- writable scratch disk 분리
- control traffic은 vsock
- TAP는 network policy가 필요할 때만 생성
- host nftables/proxy로 egress 제한
- guest shutdown 실패 시 Firecracker process 강제 종료
- VM 종료 후 scratch 폐기 또는 명시적 workspace/artifact commit만 보존

### 23.3 Environment artifact

```text
ExecutionEnvironmentRevision
        │
        ├── kernelDigest
        └── rootfsDigest
                │
                ▼
FirecrackerProvider
```

Docker/NsJail과 동일한 canonical package manifest에서 guest rootfs를 생성한다.

### 23.4 `sandboxd`

Firecracker guest의 init 과정에서 `sandboxd`를 실행한다.

```text
host executord
    │ vsock
    ▼
guest sandboxd
```

handshake에는 sandbox ID, generation, protocol version, one-time nonce를 사용한다. guest가 tenant/workspace identity를 임의로 선택할 수 없어야 한다.

### 23.5 Network

기본 `none`에서는 guest NIC 자체를 만들지 않는 것을 권장한다. control channel은 vsock만 사용한다.

네트워크가 필요할 때:

```text
guest eth0
   │ TAP
   ▼
host sandbox netns
   │ nftables/DNS proxy/egress proxy
   ▼
allowed destinations
```

### 23.6 Conformance

동일 `ExecutionEnvironmentRevision`이 NsJail, Docker, Firecracker artifact를 모두 제공하는 경우 같은 tool contract에 대해 결과 semantics를 검증한다.

비트 단위 결과가 필수는 아니지만 다음은 동일해야 한다.

- command availability
- declared file output
- exit/result classification
- workspace commit semantics
- timeout/cancel semantics
- network policy semantics
- secret exposure semantics

## 24. Backend 전환

Workspace는 backend별 cache를 가질 수 있으므로 "backend 전환"은 filesystem을 한 runtime에서 다른 runtime으로 이전하는 작업이 아니다. authoritative Workspace DO는 backend와 독립적이다.

### 24.1 Default backend 변경

Workspace default backend 변경은 다음 turn/invocation부터 사용할 기본 선택을 바꾼다.

```text
Workspace DO authoritative revision
            │
   ┌────────┼─────────┐
   ▼        ▼         ▼
 NsJail   Docker   Firecracker
 cache    cache      cache
```

변경 조건:

- active mutable execution이 없어야 함
- 현재 write lease가 없어야 함
- 현재 sandbox의 pending commit이 없어야 함

변경 절차:

```text
1. new mutable command admission 잠시 중단
2. active write lease 없음 확인
3. pending workspace commit settle 확인
4. workspace default backend CAS update
5. 필요한 경우 새 backend sandbox lazy-create
6. latest workspace revision materialize
7. health check
8. admission 재개
```

기존 backend cache는 즉시 destroy할 필요가 없으며 cache policy에 따라 idle eviction할 수 있다.

### 24.2 Session override

Session override는 workspace default와 독립적이다.

```text
Session A → nsjail
Session B → docker
Session C → firecracker
        │
        └── same Workspace W
```

단, mutable write lease는 workspace 전체에서 하나다.

### 24.3 지원하지 않는 기능

- 실행 중 process migration
- process memory snapshot 변환
- open socket 이동
- host PID/container PID/guest PID 간 이전
- sandbox local uncommitted change의 backend 간 자동 이전

## 25. Sandbox Scope

기본 `sandboxScope`는 고정 `workspace`가 아니라 `auto`다.

```yaml
execution:
  sandboxScope: auto
```

지원 값:

- `auto`
- `workspace`
- `session`
- `invocation`

### 25.1 `auto` 결정

reference policy:

```text
workspace single-owner + curated tools + raw secret 없음
    → workspace

shared workspace / user별 process state 분리 필요
    → session

unreviewed native binary / high-risk one-shot
    → invocation
```

관리자/Registry는 최소 scope를 요구할 수 있고 사용자는 더 강한 scope를 요청할 수 있다.

### 25.2 Scope 비교

| Scope | 시작 비용 | cache 효율 | process-state 격리 |
|---|---:|---:|---:|
| workspace | 낮음 | 매우 높음 | 낮음 |
| session | 중간 | 높음 | 높음 |
| invocation | 높음 | 낮음 | 매우 높음 |

### 25.3 Sandbox cache key

Scope identity만으로 sandbox를 찾으면 안 된다. 다음 전체 key가 같아야 reuse할 수 있다.

```text
scope identity
backend
ExecutionEnvironmentRevision digest
resourceProfile digest
networkPolicy digest
secretExposureClass
sandboxd protocol version
```

network policy, environment 또는 secret exposure class가 바뀌면 기존 sandbox를 그대로 재사용해서는 안 된다.

## 26. Sandbox Lifecycle

```text
absent
  │ ensureSandbox
  ▼
starting
  │ sandboxd handshake + health
  ▼
ready
  │ spawn
  ▼
busy / service-running
  │ process exit
  ▼
ready
  │ idle timeout / max lifetime / pressure
  ▼
draining
  │ no active process + pending commit settled
  ▼
stopping
  │
  ▼
absent
```

### 26.1 기본 정책

- sandbox는 lazy start
- authoritative filesystem은 Workspace DO
- sandbox cache는 폐기 가능
- maximum lifetime 이후 교체
- environment digest 변경 시 새 sandbox
- network/resource/secret exposure key 변경 시 새 sandbox
- policy/placement generation stale 시 새 invocation admission 금지
- active process가 있는 sandbox는 일반 idle eviction 대상이 아님

### 26.2 Destroy invariant

`destroy()` 완료 후 backend별 resource가 남아서는 안 된다.

NsJail:

- namespace/process
- cgroup
- control UDS
- scratch directory/quota
- network veth/nftables

Docker:

- container
- network namespace/rules
- control UDS
- scratch volume

Firecracker:

- VM process
- jail directory
- API socket
- TAP/netns/nftables
- scratch disk
- vsock allocation

cleanup가 일부 실패하면 orphan record를 남기고 reconciler가 재시도한다.

### 26.3 Reconciler

`executord` restart 이후 host에 남은 sandbox resource와 durable lease/cache record를 reconcile한다.

unknown resource를 사용자 traffic에 재사용하지 않는다. ownership을 검증할 수 없으면 destroy/quarantine한다.

## 27. MCP Gateway

MCP 연결은 Pi Worker가 raw process/network handle로 직접 관리하지 않는다.

```text
Pi Worker
    │ scoped MCP binding + TurnAuthority
    ▼
MCP Gateway
├── Local stdio MCP
└── LAN Streamable HTTP MCP
```

### 27.1 stdio MCP

stdio MCP는 장기 양방향 process가 필요하므로 `ExecutionProvider.spawn/attach/writeStdin/wait`를 사용한다.

```text
Pi Worker
    │
    ▼
MCP Gateway
    │
    ▼
ExecutionProvider
    │
    ├── NsJail
    ├── Docker
    └── Firecracker
          │
          ▼
      mcp-server process
      stdin ⇄ stdout
```

MCP Gateway가 process handle과 JSON-RPC request ID mapping을 보유한다. Pi extension에는 OS PID나 raw stdin FD를 노출하지 않는다.

stdio MCP lifecycle:

```text
ensure sandbox
→ spawn MCP server
→ initialize handshake
→ tools/list + filtering
→ repeated JSON-RPC calls
→ cancellation/health
→ server restart if policy allows
→ shutdown / sandbox eviction
```

MCP server restart 시 in-flight request를 자동 replay하려면 해당 tool의 replay policy가 이를 허용해야 한다.

### 27.2 Streamable HTTP MCP

오프라인 환경에서는 허용된 내부 endpoint만 사용한다.

```yaml
mcpServers:
  internal-git:
    transport: streamable-http
    endpointRef: lan-service/internal-git
```

raw arbitrary URL 입력 대신 admin registry의 endpoint reference를 사용하는 것을 권장한다.

### 27.3 Tool filtering

MCP server가 제공하는 모든 tool을 Pi에 그대로 노출하지 않는다.

```text
MCP tools
├── repository.read       allow
├── repository.create     allow
├── repository.delete     deny
└── organization.admin    deny
```

filter는 `tools/list` 시점뿐 아니라 실제 `tools/call` 직전에도 다시 적용한다.

### 27.4 Credential

Credential은 MCP Gateway가 보유하며 extension에는 handle만 전달한다. token passthrough를 기본 금지하고 audience/endpoint binding을 검증한다.

### 27.5 Backend affinity

stdio MCP server가 workspace/session scope로 장기 실행되는 경우 해당 MCP process는 생성 당시 backend/environment/scope cache key에 묶인다. Session backend override가 바뀌면 기존 MCP process를 다른 backend의 process로 간주해서 재사용해서는 안 된다.

### 27.6 Protocol 협상과 server-initiated request

- server별 설정에 MCP protocol version을 pin하고 initialize 협상 결과(capabilities)를 durable하게 기록한다. pin과 호환되지 않는 version 협상은 fail-closed한다.
- **server → client 방향 요청은 기본 거부한다.** sampling(`sampling/createMessage`), elicitation, `roots/list` 등은 정책으로 명시 허용한 경우에만 처리한다.
  - sampling을 허용하는 경우 Model Gateway를 경유시키고 session의 model policy/quota를 적용하며 별도 model effect로 기록한다.
  - roots는 workspace projection 경로로 제한한다.
- `tools/list_changed` 등 notification 수신 시 tool 목록을 다시 조회하고 filter를 재적용한다. 새 tool은 정책 재평가 없이 자동 노출되지 않는다.
- resources/prompts capability는 기본 미노출한다. read-only resource는 admin allowlist로 MAY 노출한다.
- Gateway는 미지원/거부 method에 JSON-RPC 표준 오류로 응답하고 audit에 기록한다.

## 28. Model Gateway

Pi Worker는 model API key나 local inference endpoint credential을 직접 받지 않는다.

```text
Pi Worker
    │ stable Model binding + TurnAuthority
    ▼
Model Gateway
├── vLLM
├── llama.cpp
├── OpenAI-compatible LAN endpoint
└── custom inference service
```

Model Gateway 책임:

- 사용자별 model allowlist
- context/token 제한
- quota
- streaming normalization
- retry 정책
- endpoint credential
- audit metadata
- cancellation
- reasoning option normalization
- provider request ID capture
- partial stream state classification

### 28.1 Model call effect

model call도 외부 effect로 취급한다.

```text
Session DO: model effect prepared
      ↓
Model Gateway request dispatch
      ↓
provider stream
      ↓
complete response settlement
```

partial stream은 기본적으로 durable assistant message로 확정하지 않는다. client에는 ephemeral `model.delta`를 보낼 수 있지만, provider 응답을 완전히 settle하기 전에는 replay semantics가 불확실함을 유지한다.

### 28.2 Retry policy

기본 규칙:

- request가 provider에 dispatch되기 전 transport failure → retry 가능
- provider가 idempotency/request-resume contract를 제공하고 검증됨 → 해당 contract에 따라 retry 가능
- 일부 output token을 이미 수신한 뒤 connection loss → 기본 자동 재요청 금지
- uncertain provider charge/request는 audit에 기록
- recovery 시 사용자가 다시 시도할 수 있으나 이전 partial output과 새 output을 하나의 응답으로 조용히 합치지 않음

### 28.3 Deferred/batch provider

provider가 durable request ID와 fetch semantics를 제공하면 `providerRequestId`를 EffectRecord에 저장하고 restart 후 fetch/resume할 수 있다.

## 29. Capability Model

Pi Worker에 서비스 접근 권한을 제공하되, 장기 bearer token을 Worker env에 직접 넣지 않는다.

### 29.1 Stable Broker Binding

Dynamic Worker `env`에는 stable RPC binding만 전달한다.

```text
Pi Worker
├── STATE
├── WORKSPACE
├── MODEL
├── MCP
├── EXECUTOR
├── ARTIFACTS
└── EVENTS
```

이 binding 자체는 다른 session/workspace identity를 문자열로 선택하는 API를 제공하지 않는다.

### 29.2 Turn Authority

실제 요청 권한은 current turn마다 발급되는 opaque authority에 묶인다.

```ts
interface TurnAuthorityClaims {
  tenantId: string;
  userId: string;
  sessionId: string;
  workspaceId?: string;
  turnId: string;

  runtimeRevision: string;

  permissions: string[];

  turnLeaseGeneration: number;
  placementGeneration: number;
  policyGeneration: number;

  issuedAt: number;
  expiresAt: number;
}
```

Extension에 claims JSON 자체를 권한 token으로 주지 않는 것을 권장한다. opaque RPC object/handle에 claims를 캡처한다.

### 29.3 검증

Broker는 최소 다음을 확인한다.

```text
signature/opaque handle validity
AND service binding match
AND current session status
AND current turn ID
AND current turn lease generation
AND current agent placement generation
AND current policy generation
AND runtime revision permitted
AND deadline not expired
AND requested operation permission
AND workspace/resource scope match
```

### 29.4 Generation 회전

다음 상황에서 관련 generation을 증가시켜 stale authority를 거부한다.

- agent shard crash/compromise 의심
- session re-placement
- runtime activation
- admin emergency policy change
- workspace ownership/security change
- credential/security incident

### 29.5 장기 session

Session이 수 시간/수일 지속되어도 Dynamic Worker를 다시 만들지 않고 capability TTL을 갱신하기 위해 env bearer token을 교체할 필요가 없어야 한다.

stable binding은 유지하고 매 turn 새 TurnAuthority를 사용한다.

### 29.6 금지 규칙

- extension이 전달한 `tenantId`, `workspaceId`, `sessionId`를 권한 판단 근거로 사용 금지
- capability/authority 원문 로그 금지
- 다른 service binding으로 authority 재사용 금지
- stale generation 허용 금지
- admin credential을 shard에 주입 금지

### 29.7 Turn 내 Authority 갱신

TurnAuthority의 TTL은 effect 실행 시간의 상한이 아니다.

규칙:

- TTL은 **신규 broker call admission**의 상한이다. 이미 dispatch된 effect의 외부 진행은 authority 만료로 중단되지 않는다.
- SessionHost는 turn이 진행 중이고 turn lease와 각 generation이 유효한 동안 만료 전에 TurnAuthority를 재발급(renewal)할 수 있다. renewal은 동일 `turnId`와 동일 generation set에 대해서만 허용한다.
- effect settlement 호출은 최초 authority의 wall-clock 만료가 아니라 현재 turn lease generation, placement generation, `effectId`/`invocationId` 일치로 검증한다. 예를 들어 30분짜리 native command의 settle은 갱신된 authority로 수행한다.
- lease가 invalid하거나 generation이 회전된 경우 renewal은 거부된다. fencing이 항상 우선한다.
- turn 전체 wall-clock 상한은 `maxTurnWallClock` 정책으로 별도 관리하며 authority TTL과 혼동하지 않는다.

## 30. Network Policy

Native sandbox의 기본 network policy는 `none`이다.

```yaml
network:
  defaultMode: none
```

지원 모드:

| 모드 | 설명 |
|---|---|
| `none` | loopback 이외 차단 |
| `mcp-only` | MCP Gateway/proxy만 허용 |
| `lan-allowlist` | 등록된 내부 destination만 허용 |
| `proxy` | egress proxy만 접근 가능 |
| `custom` | 관리자 정의 signed policy |

### 30.1 Backend별 적용

NsJail:

```text
NET namespace
+ executord-created veth when needed
+ host nftables/proxy
```

Docker:

```text
private container network namespace
+ dedicated bridge/netns
+ host nftables/proxy
```

Firecracker:

```text
no NIC for mode=none
or TAP
+ host netns
+ nftables/proxy
```

### 30.2 DNS

DNS도 policy enforcement boundary의 일부다.

- sandbox가 arbitrary resolver를 직접 지정할 수 없어야 함
- hostname allowlist를 IP direct access로 우회하지 못하게 destination IP를 검증
- DNS rebinding/TTL 변화에 대해 connection 시점 destination validation 수행
- proxy mode에서는 sandbox가 external DNS를 직접 사용할 필요가 없도록 구성

### 30.3 Network policy digest

resolved network policy를 canonicalize하여 digest를 sandbox cache key에 포함한다.

policy가 바뀌면 기존 sandbox가 더 넓은 egress를 계속 보유하지 않도록 drain/recreate 또는 host firewall 즉시 갱신을 수행한다.

### 30.4 NsJail `pasta`

NsJail의 userland networking은 development/rootless 모드에 사용할 수 있지만, reference production security policy는 host firewall/proxy가 최종 egress authority가 되는 구성을 사용한다.

## 31. Secret 관리

Secret 원문은 Pi prompt, extension config, 일반 Worker environment에 저장하지 않는다.

```text
Extension
    │ secret handle
    ▼
Credential Broker
    │ authorized use
    ├── HTTP header injection
    ├── MCP credential
    ├── invocation env/file
    └── short-lived credential
```

### 31.1 Exposure class

지원 exposure:

- `proxy-only`
- `gateway-header`
- `sandbox-env`
- `sandbox-file`
- `short-lived-token`

`proxy-only`가 기본 권장이다.

### 31.2 Sandbox secret

사용자 코드가 raw secret을 반드시 필요로 하는 경우에만 invocation 단위 env/file 노출을 허용한다.

규칙:

- secret은 sandbox cache image/rootfs에 포함하지 않음
- process spawn 직전에 주입
- command 종료 후 temporary file 삭제
- env secret을 sandboxd persistent environment에 남기지 않음
- core dump 기본 비활성화
- debug stdout/stderr redaction은 best-effort일 뿐 security boundary로 간주하지 않음
- raw secret exposure는 audit event 필수

### 31.3 Cache isolation

raw secret을 보았던 sandbox는 `secretExposureClass`를 cache key에 포함한다. 정책에 따라 invocation 종료 후 반드시 destroy할 수 있다.

## 32. Artifact Service

Workspace와 artifact를 구분한다.

```text
Workspace
├── source files
├── temporary project files
└── mutable project state

Artifact Store
├── PDF
├── PPTX
├── XLSX
├── images
├── archives
└── large final output
```

Artifact API:

```ts
interface ArtifactService {
  createFromWorkspace(
    capability: WorkspaceCapability,
    path: string,
    metadata: ArtifactMetadata,
  ): Promise<ArtifactRef>;

  open(
    capability: ArtifactCapability,
    artifactId: string,
  ): Promise<ReadableStream>;

  delete(
    capability: ArtifactCapability,
    artifactId: string,
  ): Promise<void>;
}
```

Artifact 생성도 invocation/effect ID를 가져 duplicate request가 동일 artifact를 중복 생성하는 문제를 줄인다.

Artifact download는 tenant/session/workspace ACL을 검증한 후에만 허용한다.

Artifact는 retention/quota/GC 정책을 가진다. Workspace blob과 artifact object를 같은 논리 namespace로 취급하지 않는다.

## 33. Session 요청 흐름

### 33.1 Session 생성

```text
1. Client → platformd: session 생성 요청

2. platformd:
   ├── authentication
   ├── tenant/ACL 확인
   ├── workspace 확인
   ├── extension resolve
   ├── Registry security assessment 적용
   ├── configuration snapshot
   ├── native package requirement 합성
   ├── ExecutionEnvironmentRevision resolve
   ├── execution backend resolve
   ├── Agent Isolation resolve
   └── Runtime Revision candidate 생성/검증

3. Session DO 생성
   ├── RuntimePointer.activeRevision 설정
   ├── placementGeneration 초기화
   └── policyGeneration snapshot

4. Scheduler가 agentd shard 선택

5. agentd가 target workerd shard 확보

6. SessionHost가 Dynamic Worker 생성

7. Pi AgentEngine + extension initialization

8. health check 후 session ready
```

### 33.2 Turn 실행

```text
1. Client → POST /turns + Idempotency-Key

2. Session DO:
   ├── request dedup
   ├── turn ID 할당
   ├── turn lease/generation 발급
   ├── accepted event commit
   └── TurnAuthority 생성 가능 상태 확정

3. SessionHost:
   ├── active runtime identity 확인
   └── opaque TurnAuthority와 함께 AgentEngine 호출

4. AgentEngine이 model step 요구

5. Session DO:
   └── model EffectRecord(prepared) commit

6. Model Gateway dispatch

7. client에는 ephemeral model.delta stream 가능

8. complete model response를 Session DO에 settle

9. tool call이 있으면:
   ├── EffectRecord(prepared)
   ├── Broker/ExecutionProvider/MCP 호출
   ├── external invocation ledger/commit 확인
   └── EffectRecord(settled)

10. model continuation

11. terminal assistant response + usage + turn completion을 durable commit

12. turn lease release

13. client stream completed event
```

### 33.3 Durable event와 ephemeral stream

모든 token delta를 durable journal에 저장할 필요는 없다.

Durable event 최소 집합:

```text
turn.accepted
model.effect.prepared
model.settled
tool.effect.prepared
tool.externally_committed
tool.settled
turn.needs_confirmation
turn.completed
turn.failed
turn.aborted
```

`model.delta`, `tool.stdout`, `tool.stderr`, `tool.lease.waiting`은 ephemeral stream일 수 있다. reconnect 후 durable state snapshot과 event cursor를 통해 현재 상태를 복원한다.

## 34. Turn 동시성

하나의 session은 한 시점에 하나의 active turn만 가진다.

```ts
interface TurnLease {
  turnId: string;
  ownerAgentd: string;
  ownerShard: string;
  leaseGeneration: number;
  placementGeneration: number;
  expiresAt: number;
}
```

### 34.1 Admission policy

동일 session에 동시에 여러 입력이 들어오면 기본적으로 durable queue에 넣는다.

```yaml
sessions:
  concurrentTurnPolicy: queue
```

지원:

- `queue`
- `reject`
- `cancel-previous`

### 34.2 Fencing

TurnAuthority의 `turnLeaseGeneration`과 Session DO의 현재 generation이 다르면 모든 model/tool/workspace mutation을 거부한다.

lease expiry만 보고 즉시 기존 owner의 side effect가 끝났다고 가정해서는 안 된다. 새 owner는 active EffectRecord를 복구한 뒤 다음 action을 결정한다.

### 34.3 Agent placement

agentd/shard 재배치 시 `placementGeneration`을 증가시킨다.

이전 shard가 늦게 보내는 다음 요청은 거부해야 한다.

- model dispatch
- tool dispatch
- workspace commit settlement
- turn completion
- SSE durable event append

### 34.4 Abort

Abort는 다음을 의미한다.

1. Session DO에 abort requested durable commit
2. 현재 TurnAuthority로 신규 effect admission 금지
3. active model/process에 cancellation 전달
4. safe settlement/uncertain classification 수행
5. terminal `aborted` 또는 `needs_confirmation` 상태 commit

process kill 성공만으로 외부 side effect가 없었다고 가정해서는 안 된다.

## 35. Tool Invocation 보장

외부 실행은 exactly-once라고 가정하지 않는다.

### 35.1 Effect sandwich

모든 외부 effect는 기본적으로 다음 구조를 따른다.

```text
TX(Session DO):
  "about to execute X with invocation I/request digest D"
        │
        ▼
external uncertain window
        │
        ▼
external service ledger/commit if available
        │
        ▼
TX(Session DO):
  result + external commit id + next durable state
```

### 35.2 Invocation ID

모든 외부 tool call은 globally unique invocation ID를 가진다.

예:

```text
sess_... / turn_... / effect_... / invocation_...
```

ID 자체에 secret이나 사용자 입력을 넣지 않는다.

### 35.3 Replay policy

| Mode | 의미 | Recovery |
|---|---|---|
| `safe` | 반복 실행해도 side effect 없음 | 자동 replay 가능 |
| `idempotency-key` | target이 invocation key를 dedup | 같은 key로 replay 가능 |
| `never` | 중복 실행 위험이 큼 | uncertain이면 synthetic interruption/실패 |
| `confirm` | 자동 판단 금지 | user confirmation 필요 |

manifest에서 side-effecting tool의 replay mode가 없으면 설치/Runtime Revision 생성에 실패한다.

### 35.4 Broker result ledger

가능한 서비스는 invocation ledger를 durable하게 유지한다.

```ts
interface InvocationResultRecord {
  invocationId: string;
  requestDigest: string;
  status: "inflight" | "committed" | "failed";
  externalCommitId?: string;
  resultRef?: string;
}
```

동일 invocation ID + 다른 request digest는 재사용 공격 또는 corruption으로 취급한다.

### 35.5 Workspace mutation

Workspace DO commit transaction이 invocation ledger와 new revision을 함께 기록한다. 따라서 Workspace commit 성공 후 Session DO settle 전 crash가 나도 조회로 복구할 수 있다.

### 35.6 Native command 자체의 side effect

workspace 내부 파일 변경은 Workspace DO commit으로 deduplicate할 수 있지만, command가 network를 통해 외부 시스템을 변경한 경우 workspace ledger만으로는 중복을 막을 수 없다.

예:

```text
python script
└── 내부 Git server에 mutation
```

이 경우 tool manifest는 `safe`가 될 수 없고, 외부 system의 idempotency key 또는 `confirm`/`never` 정책이 필요하다.

### 35.7 Crash recovery decision

```text
Effect state = prepared
  → dispatch 전임이 확실하면 실행 가능

Effect state = dispatched
  → external ledger 조회
     ├── committed → settle
     ├── absent + safe/idempotent → replay
     └── unknown + never/confirm → interruption/confirmation

Effect state = externally_committed
  → external effect 재실행 금지, settlement만 재개
```

### 35.8 Model effect

모델 호출도 같은 기본 구조를 따르되 partial stream은 자동 재실행에 특히 주의한다. provider가 durable request/result retrieval을 지원하지 않으면 partial-response crash는 일반적으로 uncertain effect다.

## 36. Public API

Public API는 resource identity, idempotency, durable event replay를 일관되게 지원해야 한다.

### 36.1 Capabilities

```http
GET /v1/capabilities
```

응답:

- 허용 Agent Isolation policy/profile
- NsJail availability와 unavailable reason
- Docker availability와 unavailable reason
- Firecracker/KVM availability와 unavailable reason
- available ExecutionEnvironmentRevision/profile
- resource profile
- installed extension
- model/MCP availability

### 36.2 사용자 기본 설정

```http
PUT /v1/users/me/preferences
Content-Type: application/json
```

```json
{
  "defaultExecutionBackend": "docker",
  "preferredAgentIsolation": {
    "processScope": "shared",
    "outerIsolation": "none"
  },
  "defaultExtensions": [
    {
      "id": "official/pdf",
      "version": "1.4.2"
    }
  ]
}
```

### 36.3 Workspace 생성

```http
POST /v1/workspaces
Idempotency-Key: <opaque-key>
Content-Type: application/json
```

```json
{
  "name": "algorithm-project",
  "defaultExecutionBackend": "nsjail",
  "sandboxScope": "auto"
}
```

### 36.4 Session 생성

```http
POST /v1/sessions
Idempotency-Key: <opaque-key>
Content-Type: application/json
```

```json
{
  "workspaceId": "ws_01J8XYZ",
  "extensions": [
    {
      "id": "official/pdf",
      "version": "1.4.2",
      "configuration": {
        "outputFormat": "pdf"
      }
    }
  ],
  "execution": {
    "backend": "nsjail",
    "resourceProfile": "standard"
  },
  "agentIsolation": {
    "processScope": "shared",
    "outerIsolation": "none"
  }
}
```

응답:

```json
{
  "sessionId": "sess_01J8ABC",
  "runtimeRevision": "rev_00001",
  "runtimeRevisionDigest": "sha256:...",
  "executionEnvironmentRevision": "env_standard_v1",
  "resolvedPolicy": {
    "agentIsolation": {
      "processScope": "shared",
      "outerIsolation": "none"
    },
    "executionBackend": "nsjail",
    "sandboxScope": "session",
    "networkMode": "none"
  }
}
```

### 36.5 Turn 생성

기존 `/messages`보다 durable operation identity가 명확한 `/turns`를 canonical API로 사용한다.

```http
POST /v1/sessions/{sessionId}/turns
Idempotency-Key: <opaque-key>
Content-Type: application/json
```

```json
{
  "messages": [
    {"role": "user", "content": "..."}
  ]
}
```

응답은 `turnId`를 즉시 반환하고 SSE/WebSocket stream을 연결할 수 있다.

### 36.6 Event stream

```http
GET /v1/sessions/{sessionId}/events
Last-Event-ID: 1842
```

event 예:

```text
turn.accepted              durable
model.started              durable/effect metadata
model.delta                ephemeral
model.settled              durable
tool.started               durable
tool.stdout                ephemeral
tool.artifact              durable reference
tool.completed             durable
turn.completed             durable
```

SSE reconnect 시 `Last-Event-ID` 이후 durable event를 재전송하고 현재 turn snapshot을 함께 제공할 수 있다.

### 36.7 Abort

```http
POST /v1/sessions/{sessionId}/turns/{turnId}/abort
Idempotency-Key: <opaque-key>
```

### 36.8 Runtime 변경

```http
PATCH /v1/sessions/{sessionId}/runtime
Idempotency-Key: <opaque-key>
```

이 API는 candidate Runtime Revision 생성과 staged activation을 수행한다.

### 36.9 Execution backend default 변경

Workspace default:

```http
PATCH /v1/workspaces/{workspaceId}/execution-default
```

Session override:

```http
PATCH /v1/sessions/{sessionId}/execution
```

실제 backend가 바뀌어도 Workspace DO의 authoritative file state를 migration하는 API로 취급하지 않는다.

### 36.10 Workspace file API

최소 지원:

```text
GET    /v1/workspaces/{id}/files/{path}
PUT    /v1/workspaces/{id}/files/{path}
DELETE /v1/workspaces/{id}/files/{path}
GET    /v1/workspaces/{id}/revisions
```

write는 expected revision/ETag 또는 idempotency key를 사용해야 한다.

### 36.11 Session close/delete

```text
POST   /v1/sessions/{id}/close
DELETE /v1/sessions/{id}
```

close는 active turn/effect를 controlled abort/settle한 뒤 Worker admission을 막는다. delete/retention semantics는 audit/compliance policy와 별도이며 §36.12를 따른다.

### 36.12 데이터 삭제와 export

삭제 semantics:

- session/workspace delete는 즉시 ACL revoke와 tombstone 기록을 수행하고, blob/object의 물리 삭제는 GC grace 이후에 일어난다.
- audit event는 사용자 데이터와 별도의 문서화된 retention 정책을 따르며 기간 경과 후 삭제한다.
- 기본 구성(tenant scope dedup)에서 blob 물리 삭제는 tenant 내 참조 mark 결과에만 의존한다.

Export:

- tenant-admin은 workspace archive(현재 revision snapshot)와 conversation export(JSON)를 요청할 수 있다. export 구현은 Phase 2 범위다.

## 37. 내부 서비스 구성

간단한 설치를 위해 논리 구성요소를 과도하게 microservice로 분리하지 않는다. 초기 배포는 4개의 host daemon/binary와 2개의 trusted Worker application을 중심으로 구성한다.

### 37.1 `platformd` — Go

하나의 unprivileged 프로세스에 다음 모듈을 포함한다.

- API Gateway
- Authentication
- Tenant/ACL Service
- Session Scheduler
- Extension Registry
- Capability/Authority Broker
- Model Gateway
- MCP Gateway
- Artifact Service
- Secret Service
- Policy Engine
- quota/GC coordinator

`platformd`는 Docker socket, `/dev/kvm`, host mount/network namespace 조작 capability를 가져서는 안 된다.

### 37.2 `agentd` — Go

```text
agentd
├── workerd binary supervisor
├── workerd cgroup manager
├── shard admission/pressure manager
├── shard lifecycle/recycler
├── Runtime Bundle cache
└── SessionHost bootstrap/config
```

실제 Worker Loader 호출은 workerd 안의 trusted TypeScript `SessionHost`가 수행한다.

### 37.3 `SessionHost` / `pi-runtime` — TypeScript

```text
SessionHost Worker
├── Dynamic Worker Loader binding
├── Runtime Revision verification adapter
├── stable broker bindings
└── Pi Worker lifecycle

Pi Dynamic Worker
├── AgentEngine adapter
├── Pi agent-core subset
├── extension runtime
└── lifecycle/tool dispatcher
```

### 37.4 `state-app` — TypeScript

celld에 배포되는 trusted Durable Object application이다.

```text
state-app
├── User DO
├── Session DO
├── Workspace DO
├── ExtensionState DO
├── CapabilityGeneration DO
└── Audit DO
```

### 37.5 `executord` — Go, privileged

```text
executord
├── NsJailProvider
├── DockerProvider
├── FirecrackerProvider
├── ExecutionEnvironment manager
├── sandbox scheduler/cache
├── UID/GID allocator
├── cgroup controller
├── network namespace/nftables manager
├── scratch/quota manager
├── sandboxd handshake broker
└── orphan reconciler
```

이 프로세스만 다음 privilege를 가질 수 있다.

- Docker socket, Docker backend가 enabled인 경우
- `/dev/kvm`, Firecracker backend가 enabled인 경우
- namespace/mount/network/cgroup operation에 필요한 Linux capability

가능하면 full root daemon 하나 대신 systemd sandboxing과 최소 capability set을 사용한다.

### 37.6 `sandboxd` — Go

NsJail jail, Docker container, Firecracker guest 안에서 동일한 작은 binary를 사용한다.

`sandboxd`는 다음을 가져서는 안 된다.

- Docker socket
- Firecracker API socket
- host `/dev/kvm`
- object store admin credential
- celld admin credential
- 다른 sandbox control socket

### 37.7 `platformctl` — Go

설치, init, doctor, status, backup/restore orchestration을 담당하는 단일 CLI다.

### 37.8 언어 선택

| 구성요소 | 언어 | 이유 |
|---|---|---|
| platformd | Go | 정적 배포, HTTP/SSE, concurrency, offline 운영 |
| agentd | Go | process/cgroup supervision |
| executord | Go | Docker/Firecracker/Linux namespace 연동 |
| sandboxd | Go | 작은 static-ish guest/container agent, signal/process 관리 |
| platformctl | Go | 단일 binary air-gap installer/CLI |
| SessionHost | TypeScript | stock workerd Worker Loader/RPC API 직접 사용 |
| Pi runtime | TypeScript | Pi package 및 extension ecosystem과 동일 언어 |
| state-app | TypeScript | celld Workers/Durable Object runtime |
| extension SDK/manifest compiler | TypeScript | extension authoring 및 JS module graph 처리 |

새로운 세 번째 host language를 추가하려면 운영/빌드 복잡도 증가를 정당화해야 한다.

### 37.9 내부 protocol

초기 단일 노드:

```text
platformd ↔ agentd
platformd ↔ executord
platformctl ↔ daemons
    = versioned Protobuf/Connect-style RPC over Unix domain socket
```

요구사항:

- peer UID/process permission
- UDS filesystem permission
- protocol version handshake
- request size limit
- structured error code
- deadline/cancellation

다중 노드에서는 동일 logical protocol을 mTLS HTTP/2 transport로 확장할 수 있다.

### 37.10 인증 모델

v0.3 reference 인증은 오프라인에서 완결되어야 한다.

- **Local account store.** 비밀번호는 memory-hard hash(예: argon2id)로 저장하고 bootstrap admin은 `platformctl create-admin`으로 생성한다.
- **세션과 토큰.** Web UI는 http-only cookie 세션을, API는 scope가 제한된 personal access token(PAT)을 사용한다. PAT는 해시로 저장하고 만료/revoke를 지원한다.
- **선택 연동.** LAN 내 OIDC provider와 LDAP/AD 연동은 tenant/role mapping 규칙과 함께 Phase 2 범위로 설계한다. 인터넷 IdP 의존은 비목표다.
- **MFA.** 오프라인 친화적인 TOTP를 MAY 제공한다.
- 로그인 성공/실패, lockout, PAT 발급/사용은 §48 audit event에 포함한다.

## 38. 권장 Repository 구조

```text
pi-platform/
├── go.work
├── go.mod                         # optional root module/workspace tools
│
├── cmd/
│   ├── platformd/
│   ├── agentd/
│   ├── executord/
│   ├── sandboxd/
│   └── platformctl/
│
├── internal/
│   ├── auth/
│   ├── tenant/
│   ├── acl/
│   ├── policy/
│   ├── capability/
│   ├── scheduler/
│   ├── modelgateway/
│   ├── mcpgateway/
│   ├── artifact/
│   ├── secret/
│   ├── quota/
│   ├── gc/
│   ├── agent/
│   ├── executor/
│   ├── nsjail/
│   ├── docker/
│   ├── firecracker/
│   ├── workspace/
│   └── release/
│
├── api/
│   ├── proto/
│   ├── json-schema/
│   └── generated/
│
├── workers/
│   ├── session-host/
│   ├── pi-runtime/
│   └── state-app/
│
├── packages/
│   ├── pi-adapter/
│   ├── extension-sdk/
│   ├── manifest-compiler/
│   └── protocol-types/
│
├── environments/
│   ├── definitions/
│   │   ├── minimal/
│   │   ├── python/
│   │   ├── document-tools/
│   │   └── browser/
│   ├── nsjail/
│   ├── oci/
│   └── firecracker/
│
├── sandbox/
│   ├── seccomp/
│   ├── filesystem-policy/
│   ├── nsjail-config/
│   └── sandboxd-init/
│
├── firecracker/
│   ├── kernel-config/
│   ├── rootfs-builder/
│   └── guest-init/
│
├── conformance/
│   ├── pi-workerd/
│   ├── session-state/
│   ├── effect-recovery/
│   ├── workspace/
│   ├── nsjail/
│   ├── docker/
│   ├── firecracker/
│   ├── object-store/
│   └── security/
│
├── deploy/
│   ├── systemd/
│   ├── airgap/
│   └── config/
│
└── docs/
```

upstream `computerd` fork는 core repository의 필수 component로 두지 않는다. 실험이 필요하면 `experimental/computerd-provider/`와 같이 별도 provider로 격리한다.

## 39. 단일 노드 배포

```text
Linux Host
├── platformd
├── celld
├── object store
├── agentd
│   └── workerd shards
├── executord
│   ├── NsJailProvider
│   ├── DockerProvider
│   └── FirecrackerProvider
├── nsjail binary/rootfs store
├── Docker daemon              # Docker backend enabled일 때만
└── /dev/kvm                   # Firecracker backend enabled일 때만
```

단일 노드에서도 public listener는 `platformd`만 가진다.

```text
Public:
  platformd HTTPS

Private UDS/loopback:
  celld
  object store
  agentd control
  executord control
  Docker socket
  per-sandbox control UDS
```

Firecracker guest control은 host-local vsock을 사용한다.

### 39.1 Privilege separation

reference systemd units:

```text
pi-platform.service        user=pi-platform, no host sandbox privilege
pi-agentd.service          user=pi-agent, cgroup/process supervisor privilege only
pi-executord.service       dedicated privileged service, hardened systemd unit
celld.service              dedicated user
object-store.service       dedicated user
```

`executord`가 compromise되면 host compromise 가능성이 있으므로 API surface를 매우 작게 유지한다.

## 40. 다중 노드 배포

```text
Control / State Nodes
├── platformd
├── celld
└── object store

Agent Nodes
└── agentd / workerd shards

Compute Nodes
├── executord
├── NsJail
├── optional Docker
└── optional Firecracker/KVM
```

Scheduler는 node capability를 기준으로 배치한다.

```yaml
nodeCapabilities:
  agent:
    workerd: true

  execution:
    nsjail: true
    docker: true
    firecracker: true

  architectures:
    - x86_64

  environments:
    - env_standard_v1
    - env_document_v1

  resourceClasses:
    - standard
    - heavy
```

### 40.1 Agent placement

Session은 어느 compatible agent node에서도 복원 가능해야 한다.

placement change:

```text
old agent node
   │ lease/fencing
   X
Session DO placementGeneration++
   │
   ▼
new agent node
```

### 40.2 Compute placement

Workspace sandbox도 다른 compatible compute node에서 재구축 가능해야 한다.

조건:

- 동일 ExecutionEnvironmentRevision artifact 보유/가져오기 가능
- Workspace Blob Store 접근 가능
- backend capability 충족
- network policy 지원
- architecture 일치

sandbox local cache는 node-local optimization일 뿐이다.

### 40.3 Service authentication

다중 노드 internal RPC는 mTLS와 node identity를 사용한다. node identity만으로 tenant resource access를 허용하지 않고 request에 포함된 opaque service authority를 함께 검증한다.

### 40.4 시간 동기화

- correctness의 1차 방어는 wall-clock이 아니라 fencing generation이다(§34.2).
- 그럼에도 authority deadline, lease expiry, 서명 유효기간 평가는 시계에 의존한다. 다중 노드 배포는 내부 NTP(chrony 등)로 노드 간 skew를 bounded(수 초 이내)로 유지해야 한다.
- deadline 비교에는 설정 가능한 skew 허용치를 적용하고, 허용치를 넘는 노드는 doctor/heartbeat에서 degraded로 표시하며 신규 placement에서 제외할 수 있다.
- 단일 노드는 자체 시계로 self-consistent하지만 서명/인증서 검증을 위해 설치 시 시계 sanity check를 수행한다.

## 41. 설치 프로필

설치 profile은 어떤 backend binary/daemon/artifact를 설치할지 결정한다. 사용자 session의 실제 backend 선택 정책과 동일한 개념이 아니다.

### 41.1 `lightweight`

```text
Agent:
    workerd

Native execution:
    NsJail only
```

```bash
sudo ./install.sh --profile lightweight
```

적합:

- Docker daemon 없이 작은 footprint를 원하는 서버
- curated native tool
- `/dev/kvm` 없는 환경
- 짧은 command가 빈번한 환경

reference default backend: `nsjail`

### 41.2 `docker`

```text
Agent:
    workerd

Native execution:
    Docker only
```

```bash
sudo ./install.sh --profile docker
```

적합:

- OCI image/toolchain 호환성이 중요
- 기존 Docker 운영 환경
- `/dev/kvm` 없음

reference default backend: `docker`

### 41.3 `full`

```text
Agent:
    workerd

Native execution:
    NsJail + Docker + Firecracker
```

```bash
sudo ./install.sh --profile full
```

사용자가 세 backend를 모두 선택할 수 있는 권장 기능-complete profile이다.

reference default backend는 `docker`로 두되 관리자가 `nsjail`로 변경할 수 있다. backend가 자동 fallback되는 것은 아니다.

### 41.4 `firecracker`

```text
Agent:
    workerd

Native execution:
    Firecracker only
```

```bash
sudo ./install.sh --profile firecracker
```

control plane을 systemd service로 설치하여 Docker daemon 없이 동작해야 한다.

### 41.5 `development`

```bash
sudo ./install.sh --profile development
```

- single-node
- NsJail 또는 Docker 선택 가능
- debug log
- 낮은 resource limit
- production secret 사용 금지
- broad debug capability는 production profile에 승격 금지

## 42. Air-gap Bundle

배포 파일 하나에 설치와 선택한 profile 실행에 필요한 모든 artifact를 포함한다.

```text
pi-platform-airgap-v0.3.0-linux-x86_64.tar.zst
```

release는 architecture별 별도 bundle로 배포한다. v0.3 reference target은 x86_64이며 aarch64 bundle은 Phase 2 목표다. `ExecutionEnvironmentRevision.architecture` field는 이미 이를 수용한다.

구조:

```text
bundle/
├── install.sh
├── platformctl
├── release-manifest.json
├── checksums.txt
├── signatures/
├── sbom/
│
├── bin/
│   ├── platformd
│   ├── agentd
│   ├── executord
│   ├── sandboxd
│   ├── workerd
│   ├── celld
│   ├── nsjail
│   ├── firecracker
│   ├── jailer
│   └── object-store
│
├── environments/
│   ├── registry.json
│   ├── nsjail-rootfs/
│   ├── oci-images/
│   └── firecracker/
│       ├── kernels/
│       └── rootfs/
│
├── sandbox-policy/
│   ├── seccomp/
│   ├── nsjail/
│   └── filesystem/
│
├── extensions/
│   ├── registry.json
│   ├── assessments/
│   └── bundles/
│
├── workers/
│   ├── session-host/
│   ├── pi-runtime/
│   └── state-app/
│
├── templates/
│   ├── config.yaml
│   ├── systemd/
│   └── compose/
│
└── migrations/
```

### 42.1 Release manifest

```yaml
release:
  version: 0.3.0
  architecture: x86_64

  components:
    platformd: sha256:...
    agentd: sha256:...
    executord: sha256:...
    sandboxd: sha256:...
    workerd: sha256:...
    celld: sha256:...
    nsjail: sha256:...
    firecracker: sha256:...
    jailer: sha256:...
```

모든 rootfs/image/seccomp bundle도 digest와 signature를 갖는다.

설치 이후 인터넷 접근은 필요하지 않아야 한다.

## 43. 설치 절차

### 43.1 기본 설치

```bash
tar -xf pi-platform-airgap-v0.3.0-linux-x86_64.tar.zst
cd pi-platform-airgap-v0.3.0-linux-x86_64
sudo ./install.sh --profile full
```

### 43.2 설치 작업

```text
1. release manifest, checksum, signature 검증
2. CPU architecture 확인
3. kernel/cgroup v2/namespaces 확인
4. unprivileged user namespace 및 required helper 상태 확인
5. nftables/network namespace 기능 확인
6. profile에 따라 NsJail binary/config 설치
7. profile에 따라 Docker 확인/설치 artifact 적용
8. profile에 따라 /dev/kvm 확인
9. Firecracker/jailer 설치
10. system user/group 생성
11. executord privilege/systemd hardening 적용
12. data/environment directory 생성
13. local CA와 service credential 생성
14. object store 초기화
15. bucket 생성
16. object-store CAS conformance
17. celld state app 배포
18. workerd SessionHost bundle/config 생성
19. NsJail rootfs import + digest 검증
20. OCI image import
21. Firecracker kernel/rootfs 등록
22. extension/runtime registry import
23. bootstrap admin 생성
24. platformctl doctor 실행
```

필요하지 않은 backend의 privileged component는 설치/enable하지 않는 것을 권장한다.

예: `lightweight` profile에서 Docker daemon과 `/dev/kvm` 관련 unit이 필요하지 않다.

### 43.3 초기 설정

```bash
sudo platformctl init
sudo platformctl up
sudo platformctl doctor
sudo platformctl create-admin
```

### 43.4 상태 확인

```bash
platformctl status
platformctl capabilities
platformctl doctor
```

### 43.5 Install fail-closed

다음 critical test 실패 시 관련 backend/state plane을 available로 표시하지 않는다.

- object-store CAS
- celld fencing
- workerd dynamic worker isolation
- NsJail namespace/seccomp/resource enforcement
- Docker hardening, Docker profile인 경우
- Firecracker jailer/KVM/vsock, Firecracker profile인 경우

`full` profile에서 일부 optional backend가 실패하면 설치 자체를 중단할지 해당 backend만 unavailable로 둘지는 `strictInstall` 정책으로 정하되, 실패한 backend를 usable로 표시해서는 안 된다.

## 44. `platformctl doctor`

`doctor`는 단순 process status가 아니라 실제 end-to-end security/correctness test를 실행한다.

### 44.1 Host

```text
- architecture
- kernel baseline: Linux 5.15 이상(cgroup v2 unified hierarchy 필수), 권장 6.1 이상
- cgroup v2
- user/mount/pid/net/ipc/uts namespace
- 배포판 unprivileged userns 제한(AppArmor 등) 감지와 보고. executord가 privileged launcher이므로 unprivileged userns 자체는 동작 전제조건이 아니다
- free disk/inodes
- project quota or scratch quota support
- nftables
- /dev/kvm
```

### 44.2 Object Store

```text
- bucket access
- conditional write
- ETag CAS
- concurrent CAS single winner
- read-after-write
- restart persistence
```

### 44.3 celld/state app

```text
- object creation
- SQLite transaction
- ownership fencing
- Session DO turn transaction
- recovery
- commit durability: commit 직후 kill -9 후 재시작 시 commit 내용 관찰(§15.8)
- 설정된 celld→object store 복제 RPO 검증
```

### 44.4 workerd / Pi

```text
- Dynamic Worker load
- required compatibilityDate/flags
- stable broker binding
- globalOutbound=null
- fetch/WebSocket/raw socket outbound rejection
- isolate global state separation
- content-addressed worker revision replacement
- low-level Pi AgentEngine initialization
- mock model turn
- two extension hook order
- two-session global isolation
- shard cgroup pressure/recycle smoke test
```

### 44.5 Durable effect recovery

fault injection으로 각 commit boundary 사이를 중단한다.

```text
turn accepted
model prepared
model dispatched
model settled
tool prepared
tool dispatched
workspace externally committed
tool settled
turn completed
```

재시작 후 다음을 확인한다.

- duplicate workspace mutation 없음
- unsafe tool 자동 replay 없음
- stale generation 거부
- externally committed effect는 settlement만 재개

### 44.6 NsJail

```text
- namespace 생성
- unique host UID/GID mapping
- no_new_privs
- capability drop
- read-only rootfs
- /workspace 외 host path 비가시성
- cgroup CPU/memory/PID limit
- seccomp policy violation kill/deny
- network default deny
- UDS sandboxd handshake
- process group cancellation
- workspace round trip
- destroy cleanup
```

### 44.7 Docker

```text
- sandbox creation
- non-root process
- read-only rootfs
- cap-drop/no-new-privileges
- workspace round trip
- CPU/memory/PID limits
- network deny
- Docker socket invisibility
- sandboxd UDS
```

### 44.8 Firecracker

```text
- KVM access
- jailer
- unique UID/GID
- VM boot
- vsock sandboxd handshake
- workspace round trip
- command execution
- resource limit
- no-NIC default deny
- scratch cleanup
```

### 44.9 Backend availability output

```text
NsJail       available
Docker       available
Firecracker  unavailable: /dev/kvm not found
```

UI/API는 이 결과와 server policy를 결합해 실제 선택 가능한 backend만 노출한다.

## 45. 기본 설정 파일

경로:

```text
/etc/pi-platform/config.yaml
```

Reference example:

```yaml
server:
  publicAddress: 0.0.0.0:8443
  dataDirectory: /var/lib/pi-platform

deployment:
  mode: single-node

state:
  provider: celld
  endpoint: http://127.0.0.1:8080
  readKeyId: state-read-current-1
  readRootKeyFile: /run/credentials/pi-platform/state-read.key
  dispatchStartKeyId: state-dispatch-current-1
  dispatchStartRootKeyFile: /run/credentials/pi-platform/state-dispatch-start.key
  httpTimeout: 5s
  dispatchStartTimeout: 30s
  instanceId: state-node-1
  transactionDomainId: state-domain-1
  minimumProbeEpoch: 1
  maximumEvidenceAge: 1h
  productionEvidenceFile: /etc/pi-platform/state/celld-evidence.json
  conformanceRootsFile: /etc/pi-platform/state/conformance-roots.json
  runtimeRootsFile: /etc/pi-platform/state/runtime-roots.json

objectStore:
  endpoint: http://127.0.0.1:8333
  stateBucket: pi-celld-state
  workspaceBlobBucket: pi-workspace-blobs
  artifactBucket: pi-artifacts

agent:
  runtime: workerd
  perSessionIsolate: true

  defaultIsolation:
    processScope: shared
    outerIsolation: none

  shard:
    maxResidentSessions: 200
    maximumLifetime: 6h
    memoryLimit: 4GiB
    memoryAdmissionHighWatermark: 80%
    recycleOnOom: true

execution:
  allowUserSelection: true

  allowedBackends:
    - nsjail
    - docker
    - firecracker

  defaultBackend: docker
  sandboxScope: auto
  workspaceProjection: materialized-manifest

  fallback:
    mode: disabled

executors:
  nsjail:
    enabled: true
    binary: /usr/lib/pi-platform/nsjail
    environmentRoot: /var/lib/pi-platform/environments
    cgroupRoot: /sys/fs/cgroup/pi-platform
    uniqueUidPerSandbox: true
    allowPasta: false

  docker:
    enabled: true
    mode: system
    socket: unix:///var/run/docker.sock

  firecracker:
    enabled: true
    firecrackerBinary: /usr/lib/pi-platform/firecracker
    jailerBinary: /usr/lib/pi-platform/jailer
    kernelDirectory: /var/lib/pi-platform/firecracker/kernels
    rootfsDirectory: /var/lib/pi-platform/firecracker/rootfs

workspace:
  projectionMode: materialized-manifest
  manifestVerification: full-scan
  diffStrategy: auto              # auto | full-scan | overlayfs (§17.5)
  treeManifestThreshold: 50000
  leaseWaitPolicy: queue
  leaseAcquireTimeout: 120s
  blobHash: sha256

network:
  defaultMode: none
  productionPolicyAuthority: host

models:
  default: local/primary

  endpoints:
    local/primary:
      protocol: openai-compatible
      endpoint: http://127.0.0.1:8000/v1

security:
  turnAuthorityTtl: 15m           # 신규 broker call admission 상한; effect 지속시간 상한 아님(§29.7)
  turnAuthorityRenewal: lease-bound
  maxTurnWallClock: 2h
  rotatePlacementGenerationOnShardFailure: true
  exposeRawSecretsToExtensions: false
  unreviewedExtensionMinimumOuterIsolation: firecracker

api:
  requireIdempotencyKeyForMutations: true
  durableEventRetention: 7d

retention:
  workspaceBlobGcGrace: 24h
  artifactDefault: 30d
  runtimeRollbackWindow: 24h
```

`state.endpoint`는 pin된 celld의 public Worker listener를 가리키는 명시적
port의 literal-loopback HTTP origin이어야 한다. Reference service는 celld를
`--listen 127.0.0.1:8080`으로 시작한다. celld의 internal/operator listener나
private route를 application protocol로 사용하지 않는다.

state read와 dispatch-start 권한은 서로 다른 key ID와 root-key 파일을 사용한다.
key material을 YAML에 직접 넣지 않으며, 모든 credential/evidence/root 경로는
서로 다른 canonical absolute non-root 파일이어야 한다. credential 파일 내용은
공백이나 개행이 없는 canonical lowercase hex이고, decode 결과는 32..256
bytes여야 한다. Linux startup은 모든 경로 component를 pinned descriptor로
순회하며 symbolic/magic link를 거부한다. parent는 root 또는 platformd effective
UID 소유이고 group/other writable이 아니어야 한다(root-owned sticky directory는
허용한다). 최종 파일은 platformd effective UID가 소유한 link-count 1의 regular
file이며 mode는 정확히 `0400` 또는 `0600`이어야 한다. 두 credential은 path,
device/inode, decoded key material이 모두 달라야 한다.

startup은 두 파일 descriptor를 함께 고정하고 `fstat` 전후의 identity, metadata,
size가 같은 bounded snapshot을 한 번만 읽는다. client가 key를 복사한 뒤 encoded와
decoded loader buffer를 지우며, 비-Linux build는 안전하지 않은 fallback 없이
fail-closed한다. request별 파일 재읽기는 key rotation protocol로 간주하지 않는다.
`httpTimeout`은 30초 이하, `dispatchStartTimeout`은 5분 이하,
`maximumEvidenceAge`는 24시간 이하로 fail-closed 검증한다.

production dependency의 celld build digest와 state-app application digest는 이
YAML에서 받지 않는다. 서명 검증된 release manifest의 정확한 artifact digest에서
파생하여 live probe와 conformance evidence의 descriptor에 함께 결속한다.
offline conformance signer와 live runtime signer는 서로 다른 trust domain이다.
`conformanceRootsFile`과 `runtimeRootsFile` 사이에는 key ID뿐 아니라 Ed25519
public-key material도 재사용할 수 없으며, 하나라도 겹치면 startup은 실패한다.

`maxResidentSessions`와 shard memory limit의 실제 reference 값은 Phase 0 benchmark 후 조정해야 한다. 숫자를 product invariant로 간주하지 않는다.

## 46. 리소스 Profile

### 46.1 Native sandbox resource profile

초기 reference profile:

```yaml
resourceProfiles:
  light:
    cpu: 1
    memory: 1GiB
    swap: 0
    pids: 128
    scratchDisk: 2GiB
    commandTimeout: 60s
    openFiles: 256

  standard:
    cpu: 2
    memory: 2GiB
    swap: 0
    pids: 256
    scratchDisk: 8GiB
    commandTimeout: 300s
    openFiles: 1024

  heavy:
    cpu: 4
    memory: 8GiB
    swap: 0
    pids: 512
    scratchDisk: 32GiB
    commandTimeout: 1800s
    openFiles: 4096
```

`commandTimeout`은 TurnAuthority TTL의 제약을 받지 않는다. TTL을 초과하는 장기 command의 settlement는 §29.7의 renewal과 generation 검증으로 처리한다.

동일 logical profile을 backend별로 가능한 한 같은 semantics로 변환한다.

NsJail:

```text
cgroup v2 + rlimit + scratch quota
```

Docker:

```text
container cgroup/ulimit/storage quota
```

Firecracker:

```text
vCPU + guest memory + host cgroup + scratch disk size
```

backend 특성 때문에 정확히 동일하지 않은 항목은 capability response에 차이를 표시한다.

### 46.2 Agent shard profile

Native resource와 workerd shard resource는 별도다.

```yaml
agentShardProfiles:
  standard:
    cpu: 4
    memory: 4GiB
    maxResidentSessions: 200
    maxLifetime: 6h
```

Session별 V8 heap 숫자만으로 host memory admission을 결정해서는 안 된다. shard process RSS/allocator retention을 포함한 pressure metric을 사용한다.

### 46.3 Policy clamp

관리자는 user/extension별 최대 profile과 최소 profile을 지정할 수 있다.

```yaml
policy:
  users:
    defaultMaximumResourceProfile: standard

  extensions:
    official/libreoffice:
      minimumResourceProfile: standard
```

requested resource는 policy 범위 밖으로 올라가거나 내려갈 수 없다.

## 47. 보안 경계

### 47.1 신뢰 대상

- host administrator
- platformd
- celld state application
- agentd SessionHost
- executord
- sandboxd binary 자체의 signed release
- object store service
- Extension/Environment Registry signing key

신뢰 대상이라도 최소 권한 원칙을 적용한다. 특히 `executord`는 host compromise로 이어질 수 있는 privilege를 가지므로 network/API surface를 매우 작게 유지한다.

### 47.2 잠재적 비신뢰 대상

- 사용자 입력
- model output
- 사용자 선택 extension
- extension configuration
- native binary
- stdio MCP server
- document/archive/media
- sandbox 내부 process
- 외부 LAN MCP server
- model provider/LAN service response

### 47.3 Trust boundary 요약

```text
Untrusted user/model content
       │
       ▼
Pi Worker isolate
       │ stable binding + TurnAuthority
       ▼
Broker policy boundary
       │
       ├── trusted state plane
       └── ExecutionProvider
               │
               ├── NsJail shared-kernel boundary
               ├── Docker shared-kernel boundary
               └── Firecracker microVM boundary
```

### 47.4 `shared-workerd` accepted risk

`shared-workerd`에서는 다음 위험을 수용한다.

> V8/workerd isolate escape가 발생하면 같은 workerd process에 resident한 다른 session과 tenant가 영향을 받을 수 있다.

중요한 정정:

- shared shard process memory에는 여러 resident session의 broker stub/opaque capability object가 존재할 수 있다.
- 따라서 "다른 tenant capability가 shard에 존재하지 않는다"고 가정해서는 안 된다.
- 대신 capability의 가치와 lifetime, revocation을 제한한다.

완화:

- 짧은 TurnAuthority
- server-side generation validation
- shard당 resident session 제한
- 짧은 shard maximum lifetime
- shard cgroup limit
- raw user secret 미보관
- object-store/celld/executord admin credential 미보관
- compromise 의심 즉시 generation 회전 + shard destroy

### 47.5 NsJail/Docker accepted risk

NsJail과 Docker는 host kernel을 공유한다.

> sandbox namespace/seccomp/cgroup escape 또는 host kernel exploit은 host compromise로 이어질 수 있다.

따라서 다음 workload는 Firecracker를 기본 권장한다.

- unreviewed arbitrary native binary
- 외부 사용자가 직접 제출한 hostile code
- parser exploit 위험이 높은 privileged workflow
- tenant 간 강한 kernel boundary가 요구되는 경우

NsJail은 lightweight이지만 "Firecracker와 동등한 보안"으로 표시해서는 안 된다.

### 47.6 NsJail specific trust

NsJail config, rootfs path, mount source, uid/gid map, seccomp policy는 trusted executord가 생성한다.

user/extension은 다음을 지정할 수 없다.

- raw nsjail CLI option
- raw config proto
- host bind path
- retained capability
- seccomp policy string
- cgroup path
- network interface name
- host UID/GID map

### 47.7 Firecracker boundary

Firecracker를 사용해도 host-side `executord`, jailer, KVM, kernel, device model은 TCB다. VM을 사용한다는 이유로 host network/jailer/API socket hardening을 생략해서는 안 된다.

### 47.8 Secret/credential blast radius

workerd shard에는 다음 credential을 저장하지 않는다.

- object store admin credential
- celld fleet/admin credential
- Docker socket
- `/dev/kvm`
- executord admin credential
- raw long-lived user secret

Native sandbox에도 기본적으로 위 credential을 주입하지 않는다.

### 47.9 Security policy monotonicity

최종 resolved policy는 다음 입력 중 가장 강한 요구를 만족해야 한다.

```text
server emergency policy
∩ tenant policy
∩ Registry assessment
∩ extension request
∩ user/session request
∩ host capability
```

사용자 입력이나 extension hook이 이미 적용된 최소 isolation/network/resource limit을 완화할 수 없어야 한다.

## 48. 감사 및 관측성

### 48.1 구조화 로그

필수 correlation field:

```text
timestamp
tenantId
userId
sessionId
turnId
effectId
runtimeRevision
workspaceId
agentShardId
placementGeneration
executionBackend
executionEnvironmentRevision
sandboxId
sandboxGeneration
invocationId
eventType
result
duration
resourceUsage
```

기본 로그에 저장하지 않음:

- prompt 전문
- model response 전문
- secret
- authority/capability material
- file content
- stdin/stdout 전체

### 48.2 Metric

Agent:

- active Pi Workers
- worker cold starts
- worker create failures
- shard resident sessions
- shard RSS / V8 heap aggregate
- shard pressure/recycle
- runtime activation/rollback
- turn queue length

Effect:

- effect prepared/dispatched/settled count
- uncertain effect count
- replay count by policy
- needs_confirmation count
- duplicate invocation hit
- requestDigest mismatch

Model:

- TTFT
- completion latency
- cancellation
- partial-stream failure
- provider retry

Execution:

- active NsJail sandbox
- active Docker sandbox
- active Firecracker VM
- sandbox cold start by backend/environment
- sandbox cache hit
- sandbox OOM
- command timeout
- process cancellation latency
- sandbox orphan cleanup

Workspace:

- materialize duration/bytes
- manifest scan duration
- blob upload/download
- workspace commit latency
- workspace conflict
- stale commit rejection
- invocation ledger dedup hit

Security:

- capability/authority rejection by reason
- stale generation rejection
- seccomp violation
- network policy rejection
- cross-tenant access denial

### 48.3 Audit Event

필수:

- extension install/remove
- Registry security assessment 변경
- Runtime Revision activate/rollback
- execution backend requested/resolved 변경
- ExecutionEnvironmentRevision 변경
- raw secret exposure
- network policy 변경
- admin policy 변경
- sandbox fallback, 허용된 경우
- generation rotation
- cross-tenant access reject
- NsJail/Docker/Firecracker sandbox security violation
- backup/restore

### 48.4 Tamper resistance

Audit sink는 최소한 단조 증가 sequence를 MUST 가진다. production profile에서는 hash chain과 periodic signed checkpoint를 SHOULD 사용하고, development profile에서는 MAY로 완화할 수 있다. 일반 application log가 audit authority가 되어서는 안 된다.

### 48.5 Source map

Dynamic Worker source map/stack trace가 runtime에서 완전히 해결된다고 가정하지 않는다. Agent Bundle과 source map을 digest로 저장하고 platform-side error ingestion 단계에서 remap할 수 있어야 한다.

## 49. 장애 복구

장애 복구의 기본 원칙:

```text
Durable state decides what happened.
Ephemeral process state never decides what happened.
External ledger resolves uncertain effects when possible.
```

### 49.1 Agentd/workerd 장애

```text
agentd/workerd crash
    │
    ▼
Session DO placement lease/generation change
    │
    ▼
new agentd 선택
    │
    ▼
Dynamic Worker reconstruct
    │
    ▼
active TurnState + EffectRecord inspect
    │
    ▼
resume / settle / replay / confirm
```

기존 shard의 late request는 stale placement generation으로 거부한다.

### 49.2 Pi Worker eviction

Worker Loader cache에서 Worker가 사라져도 Runtime Revision과 Session DO state로 다시 생성한다.

extension `shutdown()` 호출을 복구 전제조건으로 삼지 않는다.

### 49.3 Effect crash recovery

#### `prepared`

외부 dispatch 이전임이 보장되면 정상 실행 가능.

#### `dispatched`

외부 invocation ledger/provider request 상태를 조회한다.

```text
committed       → settlement만 재개
not found       → replay policy 평가
unknown         → never/confirm이면 자동 재실행 금지
```

#### `externally_committed`

외부 operation은 다시 실행하지 않고 Session DO settlement만 재개한다.

### 49.4 Workspace commit window

Workspace commit 성공 후 Session DO crash:

```text
Session effect = dispatched
Workspace ledger = committed(commitId=C, revision=R)
```

복구 후 `externally_committed(C,R)` → `settled`로 진행한다.

### 49.5 NsJail sandbox 장애

```text
nsjail/sandboxd crash
    │
    ├── active process interrupted
    ├── uncommitted local file may be lost
    ▼
write lease fencing
    │
    ▼
last committed Workspace revision authority
    │
    ▼
new NsJail sandbox lazy-create
```

executord는 namespace/cgroup/control socket/scratch orphan을 reconcile한다.

### 49.6 Docker container 장애

NsJail과 동일한 workspace semantics를 사용한다. container local uncommitted state는 authority가 아니다.

### 49.7 Firecracker VM 장애

NsJail/Docker와 동일한 workspace semantics를 사용한다. VM memory state는 복구 대상이 아니다.

### 49.8 Executord 장애

restart 후:

```text
1. durable/host sandbox registry load
2. NsJail process/cgroup scan
3. Docker container label scan
4. Firecracker jail/process scan
5. ownership/generation validate
6. attach 가능한 healthy sandbox는 policy에 따라 재등록
7. 불명확하거나 stale한 resource는 quarantine/destroy
8. active effect는 Session DO가 recovery 결정
```

Executord가 process를 발견했다고 해서 그 process의 command가 성공했다고 추론해서는 안 된다.

### 49.9 celld 장애

celld의 object ownership/fencing와 object-store durable state를 사용해 복구한다. stale owner write가 수락되지 않는 것을 doctor/fault test로 검증한다.

### 49.10 Object Store 장애

- new durable commit fail-closed
- 성공하지 않은 write를 성공으로 응답 금지
- read-only degraded mode는 explicit admin policy
- 복구 후 consistency/CAS check
- workspace blob upload 성공 + metadata commit 실패 object는 GC grace 후 수거

### 49.11 Workerd escape 의심

```text
1. shard admission 중단
2. affected placementGeneration/policy generation rotate
3. shard 강제 종료
4. resident session interrupted 표시
5. 새 shard에서 session reconstruct
6. active effect recovery
7. audit/incident 기록
```

### 49.12 Host reboot

single-node reboot 후 다음 순서로 시작한다.

```text
object store
→ celld
→ platformd state readiness
→ agentd
→ executord reconcile
→ API admission
```

sandbox cache는 모두 없어도 정상 동작해야 한다.

## 50. 업그레이드

모든 component와 execution artifact는 release manifest로 고정한다.

```yaml
release:
  version: 0.3.0

  components:
    workerd: sha256:...
    celld: sha256:...
    piRuntime: sha256:...
    platformd: sha256:...
    agentd: sha256:...
    executord: sha256:...
    sandboxd: sha256:...
    nsjail: sha256:...
    firecracker: sha256:...
    jailer: sha256:...
```

### 50.1 Upgrade order

```text
1. 새 air-gap bundle signature/digest 검증
2. state/object store backup
3. state migration dry-run
4. new Environment/Extension artifacts import
5. platformd compatibility check
6. state-app migration/deploy
7. 새 agentd/workerd shard 생성
8. 기존 session 순차 drain/re-placement
9. executord upgrade
10. 신규 sandbox부터 새 sandboxd/backend binary 사용
11. old sandbox는 max lifetime/drain으로 교체
12. conformance/doctor
13. rollback window 유지
14. old artifact GC
```

### 50.2 Runtime Revision과 platform upgrade

진행 중 Session의 extension/runtime configuration을 자동으로 새 버전으로 바꾸지 않는다. 다만 security emergency로 old workerd/runtime을 금지해야 하는 경우 admin policy가 강제 Runtime Revision migration을 수행할 수 있다.

### 50.3 Protocol compatibility

rolling upgrade 동안 다음 version pair의 compatibility matrix를 release manifest에 포함한다.

- platformd ↔ agentd
- platformd ↔ executord
- SessionHost ↔ Dynamic Worker ABI
- executord ↔ sandboxd
- state-app schema

지원하지 않는 pair는 connection/admission 단계에서 fail-closed한다.

### 50.4 Environment upgrade

ExecutionEnvironmentRevision은 immutable하다. package update는 기존 environment rootfs/image를 mutate하지 않고 새 environment revision을 만든다.

기존 sandbox는 old environment digest로 drain하고, 새 invocation부터 new digest를 사용할 수 있다.

## 51. 구현 단계

구현 단계는 experimental component와 새로운 protocol을 동시에 너무 많이 도입하지 않도록 vertical slice 중심으로 나눈다.

각 phase에는 명시적 컷 라인을 둔다. 일정 압박 시 Registry 서명 강제화의 유예, quota 세분화, `tenant-workerd`/`session-workerd` profile 등은 뒤로 미룰 수 있다. 그러나 §55 불변식과 §53.2/§53.5의 durable correctness 테스트는 어떤 컷에서도 제외하지 않는다. §53 acceptance matrix 전체가 상당한 구현량이므로 phase별 필수 부분집합을 conformance suite에서 태그로 관리한다.

### 51.1 Phase 0A — Pi/workerd 실행 검증

목표:

- exact Pi commit/package와 stock workerd binary pin
- static SessionHost Worker
- Dynamic Worker Loader
- Dynamic Worker당 Pi 하나
- low-level Pi AgentEngine
- mock model binding
- mock tool binding
- lifecycle extension 2개
- in-memory/mock durable state

필수 test:

```text
✓ Pi core bundle이 허용되지 않은 Node builtin에 의존하지 않음
✓ one model/tool turn 완료
✓ two session global state 비공유
✓ deterministic hook ordering
✓ globalOutbound=null
✓ fetch/WebSocket/raw socket outbound deny
✓ infinite JS CPU 제한/worker failure 처리
✓ content-addressed runtime identity
✓ Worker kill 후 reconstruction
✓ shard RSS/cold-start benchmark
```

Go/No-Go:

- 필요한 Pi subset이 workerd에서 실행되지 않으면 full coding-agent port 중단
- 최소 agent loop/agent-core subset만 유지한 `pi-worker-runtime` 구현
- broad Node compatibility를 켜서 host privilege를 되살리는 방식은 금지

### 51.2 Phase 0B — Durable turn/effect state machine

실제 native backend 없이 mock external service로 구현한다.

범위:

- Session DO turn state
- EffectRecord
- TurnAuthority/fencing generation
- durable event cursor
- mock Workspace invocation ledger
- API Idempotency-Key
- fault injection framework

각 durable transition 전후에 kill/restart를 삽입한다.

```text
accepted
→ model_prepared
→ model_dispatched
→ model_settled
→ tool_prepared
→ tool_dispatched
→ tool_external_commit
→ tool_settled
→ completed
```

완료 조건:

```text
✓ duplicate external mutation 없음
✓ unsafe replay 없음
✓ stale agent request reject
✓ crash window마다 deterministic recovery outcome
✓ SSE reconnect snapshot/event replay
```

### 51.3 Phase 1A — NsJail single-node vertical slice

NsJail을 첫 lightweight provider로 구현한다. 이 단계에서는 environment 하나만 지원한다.

범위:

- platformd
- state-app/celld
- object store
- agentd/workerd
- executord
- sandboxd
- NsJailProvider
- `minimal-v1` 또는 `standard-v1` ExecutionEnvironmentRevision 하나
- materialized-manifest workspace
- content-addressed workspace blob
- local model gateway
- basic Auth/Tenant/ACL
- air-gap lightweight profile

제외:

- Docker
- Firecracker
- FUSE
- upstream computerd
- stdio MCP 장기 server
- browser/CUA
- dynamic environment composition

완료 조건:

```text
✓ offline install
✓ per-session Pi isolate
✓ native command through NsJail
✓ workspace commit/recovery
✓ seccomp/network/resource enforcement
✓ end-to-end durable turn/effect recovery
✓ platformctl doctor --backend nsjail
```

NsJail rootfs packaging이 운영상 예상보다 큰 장애가 되는 경우 DockerProvider를 먼저 구현할 수 있지만, 동시에 두 provider를 디버깅하며 Phase 1 correctness를 검증해서는 안 된다.

### 51.4 Phase 1B — Docker provider + long-lived process/MCP

범위:

- DockerProvider
- same sandboxd protocol
- `spawn/attach/writeStdin/wait`
- stdio MCP
- NsJail/Docker environment conformance
- sandbox cache key/scope auto
- rootless Docker optional

완료 조건:

```text
✓ same tool contract on NsJail/Docker
✓ stdio MCP selected backend에서만 실행
✓ process cancellation/backpressure
✓ workspace commit identical semantics
```

### 51.5 Phase 2 — 운영/보안 완성

범위:

- Registry signed assessment
- quota/GC
- backup/restore drill
- runtime staged activation/rollback
- extension state migration
- tenant-workerd/session-workerd
- shard pressure admission/recycle
- audit hardening
- secret exposure policy
- security emergency overlay
- upgrade protocol compatibility gates

이 단계까지 완료된 NsJail/Docker profile을 첫 production candidate로 삼는다.

### 51.6 Phase 3 — Firecracker

범위:

- FirecrackerProvider
- jailer
- rootfs/kernel builder
- vsock sandboxd
- TAP/netns/nftables
- unique UID/GID/vsock CID allocation
- no-NIC default
- NsJail/Docker/Firecracker conformance
- backend-specific cache coexistence

완료 조건:

```text
✓ hostile/high-risk profile can require Firecracker
✓ no silent fallback
✓ workspace switch has no filesystem migration semantics
✓ KVM unavailable reason explicit
✓ guest network default deny
✓ crash/recovery parity
```

### 51.7 Phase 4 — Sandboxed agent / multi-node / interactive services

범위:

- outer-isolated workerd
- unreviewed extension → session workerd + Firecracker policy
- agent node scheduler
- compute node scheduler
- mTLS internal RPC
- session re-placement
- sandbox rebuild on other node
- celld multi-node operational test
- browser/CUA `InteractiveServiceProvider`

Browser/CUA는 단순 `exec()`의 확장으로 억지로 표현하지 않고 화면/입력/long-lived service가 필요하면 별도 provider contract를 추가한다.

## 52. 주요 위험과 대응

| 위험 | 영향 | 대응 |
|---|---|---|
| Pi의 Node API 의존성 | workerd port 지연 | low-level Pi subset + AgentEngine adapter, Phase 0A gate |
| Pi와 플랫폼의 중복 state machine | crash 후 replay 모순 | Session DO 단일 durable program counter |
| workerd Worker Loader API 변화 | runtime bootstrap break | exact binary pin, compatibility/ABI digest, conformance |
| workerd sandbox escape | shared shard session/tenant 침해 | process scope 강화, outer isolation, shard limits, generation rotation |
| per-isolate memory control 부족 | shard OOM | process cgroup, resident limit, pressure admission/recycle |
| celld alpha/운영 안정성 | state plane 장애 | pinned release, abstraction, backup, fault tests, single-node 우선 |
| Cross-DO transaction 부재 | workspace commit 후 session 상태 불일치 | EffectRecord + Workspace invocation ledger + externalCommitId |
| unsafe tool replay | side effect 중복 | mandatory replay mode, idempotency/confirm/never |
| capability TTL 고정 env | 장기 session 만료/재발급 문제 | stable binding + per-turn authority |
| stale worker late write | double completion/corruption | turn/placement/policy fencing generation |
| extension snapshot이 authority화 | upgrade/restore 영구 block | snapshot은 optimization, durable state는 ExtensionState |
| extension hook patch 충돌 | 비결정/정책 우회 | deterministic composition + post-policy validation |
| native package 충돌 | sandbox image 선택 불가 | ExecutionEnvironmentRevision resolver |
| NsJail rootfs 관리 부재 | 운영/패키징 복잡도 | curated immutable rootfs artifact + canonical env builder |
| NsJail host kernel 공유 | kernel escape 시 host compromise | shared-kernel 명시, strict namespace/seccomp, high-risk는 Firecracker |
| NsJail config/mount injection | host path/privilege escape | executord-generated config, user raw option 금지 |
| Docker socket 노출 | host compromise | executord만 socket 접근 |
| Firecracker network/jailer 설정 오류 | host/LAN 접근 또는 격리 약화 | jailer, netns/nftables, doctor/fault tests |
| Workspace diff 누락 | 파일 유실 | post-exec canonical full manifest as correctness baseline |
| Symlink/device special file | workspace escape/semantic mismatch | restricted canonical filesystem subset |
| Backend 결과 차이 | 재현성 저하 | common environment manifest + conformance suite |
| Backend cache + session override 충돌 | 잘못된 sandbox reuse | full cache key + workspace-wide single write lease |
| stdio MCP에 one-shot API 사용 | protocol 불가/취소 문제 | spawn/attach/writeStdin/wait provider API |
| Secret가 persistent sandbox에 잔류 | credential exposure | invocation injection, exposure class cache key, optional destroy |
| Object store CAS 불일치 | celld state 손상 | install-time real CAS test |
| Orphan sandbox resource | privilege/resource leak | executord reconciler |
| Silent backend fallback | 예상보다 약한 isolation | default disabled, requested/resolved audit |
| Dynamic bundle supply-chain | extension compromise | hermetic build, lock, SBOM, signature, Registry assessment |
| API duplicate request | 중복 turn/session | Idempotency-Key durable dedup |
| Object/blob 누적 | disk exhaustion | quota + mark-and-sweep GC |
| 장기 tool 실행 중 authority 만료 | settle 거부/turn 실패 | TTL을 admission 상한으로 한정, lease-bound renewal, generation 기반 settle 검증 |
| 병렬 tool call 처리 미정의 | provider 호환성 문제/effect 중복 | 결정적 직렬화 규칙 + 순차 effect 불변식 |
| 대형 workspace full-scan 비용 | command당 지연 급증 | overlayfs diff, tree manifest, node-local blob cache, read-only invocation |
| celld durability 가정 미충족 | durable state 유실/모순 | §15.8 요구 계약, doctor durability/RPO 검증, 백업 RPO/RTO |

## 53. 필수 Acceptance Test

### 53.1 Session/Pi/Extension isolation

- 같은 extension을 두 session에 로드해도 global variable이 공유되지 않는다.
- 같은 user의 두 session도 lifecycle state를 공유하지 않는다.
- Alice extension이 Bob config/state를 읽을 수 없다.
- 동일 tool name 충돌 시 Runtime Revision 생성이 실패한다.
- runtime activation이 old active turn을 중간에 교체하지 않는다.
- old Worker drain 후 stale hook/effect 호출이 generation으로 거부된다.
- Worker eviction 후 `initialize()` 재실행으로 correctness가 깨지지 않는다.

### 53.2 Single durable state machine

- Session DO의 TurnState만 durable program counter로 사용된다.
- Pi adapter에 별도 authoritative operation journal이 없다.
- crash 후 현재 action을 "없는 record 추론"이 아니라 persisted state로 결정한다.
- future AgentHarness adapter를 사용해도 duplicate program counter가 생기지 않는 conformance contract를 가진다.
- 하나의 turn에서 두 개 이상의 effect가 동시에 `dispatched` 상태가 되지 않는다.
- 복수 tool call을 포함한 model 응답이 선언 순서대로 직렬 실행되고 각 결과가 순서대로 settle된다.

### 53.3 Worker Loader

- required compatibility date가 Runtime Revision에 pin된다.
- compatibility flag change가 runtime identity digest를 바꾼다.
- loader cache logical name 재사용으로 old code가 잘못 재사용되지 않는다.
- globalOutbound가 차단된다.
- direct fetch/WebSocket/raw socket smoke test가 실패한다.
- workerd shard cgroup memory/CPU limit이 적용된다.

### 53.4 Turn Authority/Capability

- forged workspace ID로 다른 workspace 접근 불가.
- 다른 session authority 재사용 불가.
- expired TurnAuthority 거부.
- turn lease generation 회전 후 stale request 거부.
- placement generation 회전 후 old shard 거부.
- policy generation 회전 후 이전 권한 거부.
- long-running session에서 env bearer token 교체 없이 새 turn authority 발급 가능.
- authority TTL을 초과하는 native command(예: heavy profile 30분) 실행 중 renewal로 settlement가 성공한다.
- lease invalid 또는 generation 회전 이후의 renewal 요청은 거부된다.

### 53.5 Effect recovery fault matrix

다음 각 boundary 직전/직후 process kill을 자동 주입한다.

```text
turn.accepted
model.prepared
model.dispatched
model.settled
tool.prepared
tool.dispatched
external.commit
tool.settled
turn.completed
```

검증:

- `safe`만 자동 replay.
- `idempotency-key`는 동일 key 사용.
- `never` uncertain effect 재실행 안 함.
- `confirm`은 needs_confirmation.
- externally committed effect는 재실행 없이 settle.

### 53.6 Runtime Revision

- candidate health check 실패 시 activeRevision 유지.
- candidate state migration 실패 시 old state/revision 유지.
- CAS activation 전 새 revision으로 user turn admission 안 됨.
- activation 후 old Worker의 new turn admission 거부.
- rollback은 다음 turn runtime만 변경하고 이미 발생한 side effect를 되돌린다고 주장하지 않음.

### 53.7 Execution Environment Resolution

- extension package requirement 합집합이 curated environment 하나로 resolve된다.
- version conflict 시 session creation 실패.
- backend artifact가 없는 environment에서는 해당 backend 선택 불가.
- environment digest 변경 시 sandbox cache miss/new sandbox.
- extension이 raw Docker image/NsJail rootfs/Firecracker path를 임의 지정할 수 없다.

### 53.8 Workspace filesystem

- direct write가 Workspace DO revision으로 durable하다.
- file create/modify/delete/rename/chmod가 manifest diff에 반영된다.
- absolute symlink 거부.
- workspace 밖으로 escape하는 symlink 거부.
- device/FIFO/socket durable commit 거부.
- large file blob upload + metadata commit 동작.
- sandbox kill 후 last committed revision 복원.
- stale sandbox commit 거부.
- 동시에 두 mutable writer lease 획득 불가.
- write 권한 없는 invocation이 lease 없이 실행되고 `/workspace` write가 차단된다.
- overlayfs diff를 지원하는 구성에서 overlay mutation set과 full-scan diff 결과가 동일하다.

### 53.9 Workspace cross-DO commit

- Workspace commit 성공 직후 agent kill.
- Session effect는 unsettled 상태로 남음.
- recovery가 Workspace invocation ledger를 조회.
- 동일 mutation을 다시 적용하지 않고 previous `workspaceCommitId`로 settle.
- same invocationId + different requestDigest는 reject.

### 53.10 NsJail

- USER/MOUNT/PID/IPC/UTS/NET namespace 적용.
- sandbox host UID/GID가 policy대로 매핑.
- rootfs read-only.
- `/workspace`/`scratch` 외 write 금지.
- host `/home`, `/root`, platform data, Docker socket, `/dev/kvm` 미노출.
- no_new_privs 유지.
- retained capability 없음.
- seccomp deny test 성공.
- cgroup CPU/memory/PID limit 적용.
- default network deny.
- timeout/cancel 시 process tree/cgroup 종료.
- sandboxd private UDS만 접근 가능.
- destroy 후 namespace/cgroup/veth/scratch cleanup.

### 53.11 Docker

- non-root UID.
- Docker socket 미노출.
- read-only rootfs.
- cap-drop ALL/no-new-privileges.
- CPU/memory/PID limit.
- default network deny.
- timeout 시 process tree 종료.
- private sandboxd UDS.

### 53.12 Firecracker

- jailer 사용.
- microVM마다 unique UID/GID.
- API socket 일반 사용자 접근 불가.
- control channel vsock.
- mode=none에서 guest NIC 없음.
- VM 종료 후 scratch 폐기.
- `/dev/kvm` 미지원 시 silent fallback 없음.

### 53.13 Backend coexistence/switch

- 같은 workspace에 NsJail/Docker/Firecracker cache가 존재해도 mutable lease는 하나.
- Session A NsJail, Session B Docker가 same workspace read 가능.
- sequential write 후 다음 backend가 latest committed revision을 봄.
- backend default 변경이 local uncommitted state migration을 시도하지 않음.
- cache key의 network/environment/security class가 다르면 reuse 안 됨.

### 53.14 MCP

- stdio MCP가 selected backend에서 실행.
- NsJail 선택 시 NsJail 밖에 server process 생성 안 됨.
- Docker 선택 시 container 밖에 server process 생성 안 됨.
- Firecracker 선택 시 guest 밖에 server process 생성 안 됨.
- multiple JSON-RPC request를 같은 long-lived process에 전달 가능.
- cancellation과 server death 처리.
- denied MCP tool 실제 call 단계에서도 거부.
- credential raw value가 Pi Worker에 전달되지 않음.
- server-initiated sampling/elicitation 요청이 기본 거부되고 audit에 기록됨.
- MCP protocol version pin 불일치 시 fail-closed.

### 53.15 Secret

- proxy-only secret raw value가 sandbox/Worker에 없음.
- sandbox-env/file secret 사용 audit.
- temp file cleanup.
- secret exposure class 변경 시 sandbox reuse policy 적용.

### 53.16 API/SSE

- duplicate `Idempotency-Key` turn create가 하나의 turn만 생성.
- same key + different body digest는 conflict.
- SSE disconnect/reconnect 후 durable event 중복 없이 복원.
- ephemeral delta loss가 durable turn state를 손상시키지 않음.

### 53.17 ACL/quota

- 다른 tenant resource ID를 알아도 접근 불가.
- workspace member/owner role 적용.
- sandbox/session/blob quota 초과 admission 거부.
- quota 거부가 partial durable mutation을 남기지 않음.

### 53.18 Install/upgrade

- internet blocked clean Linux에서 lightweight profile 설치.
- Docker profile이 KVM 없이 설치.
- Firecracker profile이 Docker 없이 설치.
- full profile이 세 backend availability를 독립 검증.
- object-store CAS failure 시 state plane start 금지.
- unsupported internal protocol version fail-closed.
- upgrade rollback window 동안 previous runtime artifact 유지.
- 설치 직후 doctor end-to-end turn 완료.

## 54. 최종 권장 기본 구성

기능-complete reference deployment의 기본값:

```yaml
agent:
  perSessionIsolate: true

  defaultIsolation:
    processScope: shared
    outerIsolation: none

  shard:
    boundedResidentSessions: true
    cgroupLimits: true
    recycleOnPressure: true

execution:
  allowUserSelection: true

  allowedBackends:
    - nsjail
    - docker
    - firecracker

  # Full profile의 compatibility-oriented default.
  # Lightweight profile은 nsjail을 default로 override한다.
  defaultBackend: docker

  sandboxScope: auto
  fallback:
    mode: disabled

workspace:
  provider: celld
  projectionMode: materialized-manifest
  authoritativeState: workspace-do
  contentStore: content-addressed
  mutableWriterLimit: 1

network:
  defaultMode: none

state:
  turnAuthority: session-do
  effectAuthority: session-do
  workspaceAuthority: workspace-do

capability:
  model: stable-binding-plus-turn-authority
  serverSideGenerationCheck: true

extensions:
  unreviewedPolicy:
    processScope: session
    outerIsolation: firecracker

sandbox:
  agent: sandboxd
  lazyStart: true
  persistentProcessState: false
```

### 54.1 사용자 UI

기본 사용자 선택은 단순하게 유지한다.

```text
Extensions
    필요한 기능 선택

실행 환경
    NsJail      Lightweight
    Docker      Container
    Firecracker MicroVM

리소스
    Light
    Standard
    Heavy
```

각 backend 옆에는 다음 정보만 명확히 보여준다.

- host kernel 공유 여부
- 현재 available 여부
- extension/environment compatibility
- 예상 startup/resource class

Agent Isolation은 기본적으로 admin/Registry policy가 자동 결정하고 고급 설정에서 더 높은 격리만 요청할 수 있게 한다.

### 54.2 권장 선택

- 내부 curated CLI/문서 tool, 낮은 overhead 우선 → NsJail
- OCI 호환성과 범용 toolchain 우선 → Docker
- hostile/unreviewed native code 또는 강한 tenant boundary → Firecracker

이 분류는 absolute security ranking이 아니라 reference policy다. NsJail/Docker는 shared-kernel class라는 사실을 UI에서 숨기지 않는다.

## 55. 최종 아키텍처 불변식

구현 전반에서 다음 규칙을 깨뜨려서는 안 된다.

```text
1. 하나의 session은 하나의 Pi Worker isolate를 가진다.

2. 같은 사용자의 서로 다른 session도 Pi instance/global state를 공유하지 않는다.

3. 선택된 extension은 해당 session의 Pi Worker 안에서 lifecycle graph를 구성한다.

4. 설정/extension/workerd compatibility 변경은 새 Runtime Revision으로 처리한다.

5. Session/turn에는 authoritative durable program counter가 정확히 하나만 존재한다.

6. 초기 authority는 Session DO이며 Pi AgentEngine은 step executor다.

7. Pi Worker/workerd shard는 authoritative state를 소유하지 않는다.

8. celld는 trusted state plane으로만 사용한다.

9. Workspace DO가 file metadata/revision/write lease의 최종 authority다.

10. file bytes는 content-addressed blob으로 저장할 수 있으나 sandbox local filesystem은 authority가 아니다.

11. 외부 effect는 exactly-once라고 가정하지 않는다.

12. 모든 side-effecting tool은 replay policy를 명시한다.

13. Workspace external commit과 Session settlement 사이 crash window를 정상적으로 복구해야 한다.

14. stale turn/placement/policy generation의 request는 거부한다.

15. Dynamic Worker env에는 long-lived raw bearer secret 대신 stable broker binding을 둔다.

16. turn별 실제 권한은 짧은 opaque TurnAuthority에 묶는다.

17. extension hook은 외부 side effect를 직접 수행하지 않고 Broker effect 경계를 사용한다.

18. extension snapshot/shutdown은 correctness의 authority가 아니다.

19. 여러 extension의 native package는 하나의 immutable ExecutionEnvironmentRevision으로 resolve한다.

20. native binary는 반드시 NsJail, Docker 또는 Firecracker ExecutionProvider를 통해 실행한다.

21. NsJail/Docker는 host kernel을 공유하며 Firecracker와 동일한 경계로 표현하지 않는다.

22. Docker/NsJail/Firecracker 선택과 Pi extension isolation은 별개의 정책이다.

23. extension/user는 host filesystem path, Docker socket, NsJail raw config, /dev/kvm을 지정/접근할 수 없다.

24. Dynamic Pi Worker는 기본적으로 직접 outbound network를 갖지 않는다.

25. Native sandbox network도 default deny다.

26. sandbox는 언제든 폐기하고 authoritative state에서 재생성할 수 있어야 한다.

27. sandbox reuse는 backend/environment/network/resource/security-class 전체 cache key가 같을 때만 허용한다.

28. workspace에는 backend별 cache가 공존할 수 있지만 mutable write lease는 하나다.

29. 사용자가 요청한 backend를 조용히 다른 backend로 바꾸지 않는다.

30. NsJail, Docker, Firecracker는 동일한 process/workspace semantics의 ExecutionProvider contract를 구현한다.

31. stdio MCP는 long-lived process API로 구현하며 one-shot exec를 가장하지 않는다.

32. API mutation은 idempotency semantics를 갖는다.

33. SSE/WebSocket stream loss가 durable turn outcome을 바꾸지 않는다.

34. Registry trust assessment는 extension manifest의 자기 주장으로 대체할 수 없다.

35. 설치 이후 인터넷 연결 없이 전체 기능과 복구가 동작해야 한다.

36. 하나의 turn에서 external effect는 한 시점에 최대 하나만 in-flight이며, 병렬 tool call은 결정적으로 직렬화한다.

37. TurnAuthority TTL은 신규 admission의 상한일 뿐이며, renewal은 유효한 turn lease와 generation에서만 허용되고 settlement 검증은 generation을 따른다.

38. celld state plane은 §15.8의 내구성 계약을 충족해야 하며, upgrade마다 재검증한다.
```

이 구조를 기준으로 일반 session은 저비용 workerd isolate로 높은 밀도로 실행하고, native 작업은 NsJail/Docker/Firecracker 중 명시적으로 선택할 수 있다. Workspace와 turn state는 backend/process lifetime과 분리되어 있으므로 향후 browser, CUA, document generator, custom binary를 추가할 때도 core durable state model을 유지할 수 있다.



---

## Appendix A. 외부 컴포넌트 검증 기준

이 절은 2026-08-22 기준으로 외부 프로젝트의 공식 문서와 소스에서 확인한 사실을 정리한다. 구현은 항상 release manifest에 pin된 정확한 binary/source digest를 기준으로 다시 검증해야 하며, 이 절의 서술만으로 특정 버전의 동작을 가정해서는 안 된다.

### A.1 NsJail

`google/nsjail`은 OCI container engine이 아니라 Linux namespace, cgroup, rlimit, seccomp-bpf 및 제한된 filesystem view를 조합하여 프로세스를 격리하는 sandbox다. 공식 구현에서 USER, MOUNT, PID, IPC, UTS, NET, CGROUP 및 선택적인 TIME namespace, chroot/pivot-root, read-only bind mount와 tmpfs, cgroup v1/v2, rlimit, Kafel 기반 seccomp-bpf를 지원한다.

본 플랫폼은 NsJail을 다음과 같이 사용한다.

- NsJail은 `lightweight shared-kernel sandbox`이며 VM 보안 경계로 분류하지 않는다.
- 실행 환경의 rootfs, seccomp policy, mount graph와 uid/gid mapping은 사용자가 직접 지정하지 않고 `ExecutionEnvironmentRevision`에서 resolve한다.
- `executord`만 NsJail launcher와 host path를 제어한다.
- sandbox 내부의 control plane은 `sandboxd`이며 private Unix-domain socket으로만 접근한다.
- `no_new_privs`를 유지하고 capability를 제거하며, USER/MOUNT/PID/IPC/UTS/NET namespace를 기본 활성화한다.
- CPU, memory, PID 등의 hard quota는 host cgroup v2가 최종 authority이고 rlimit은 보조 제한으로 사용한다.
- network는 기본적으로 isolated network namespace이며, 허용 시에만 executord가 생성한 veth/netns/nftables 또는 proxy 경로를 사용한다.
- 임의의 hostile binary 또는 kernel attack surface가 중요한 workload에는 Firecracker를 우선한다.

### A.2 workerd

workerd는 V8 isolate를 사용하지만 공식 프로젝트도 이를 악의적 코드에 대한 hardened security sandbox로 간주하지 않는다. 따라서 `shared` 또는 `tenant` process scope는 신뢰된/검토된 extension의 비용 최적화 경계이며, 신뢰할 수 없는 extension에는 별도의 outer sandbox 또는 Firecracker 기반 격리를 사용한다.

Dynamic Worker 생성에 사용되는 workerd ABI, compatibility date/flags, loader ABI와 resource-limit semantics는 release manifest에 pin하고 Phase 0 및 업그레이드 conformance test에서 재검증한다.

### A.3 celld와 sandbox runtime

celld에는 플랫폼이 신뢰하는 state application만 배포하며 사용자 extension을 실행하지 않는다. Native sandbox의 filesystem 또는 process state는 authoritative state가 아니며, sandbox 종류와 무관하게 Workspace DO와 Session DO의 durable protocol이 최종 authority다.

### A.4 외부 컴포넌트 변경 대응

다음 변경은 일반 dependency update로 처리하지 않고 compatibility gate를 통과해야 한다.

- workerd binary, compatibility behavior 또는 Worker Loader ABI 변경
- Pi runtime/adapter ABI 변경
- celld state/storage protocol 변경
- NsJail binary, kernel namespace/seccomp/cgroup behavior 변경
- Docker daemon/runtime 또는 default seccomp behavior 변경
- Firecracker/jailer/kernel/rootfs 변경
- sandboxd protocol 변경

Compatibility gate가 실패하면 기존 runtime revision과 execution environment revision을 유지하고 업그레이드를 중단해야 한다.
