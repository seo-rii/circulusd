# circulusd-test

`../circulusd`의 실제 Pi runtime 엔진(`@circulusd/pi-runtime`)을 그대로 가져와 한 턴을 끝까지
돌려보는 **아주 작은 에이전트 테스트용 프론트엔드/백엔드**입니다. circulusd 본체는 아직
프로덕션 워크로드 그래프가 완성되지 않았기 때문에, 이 프로젝트가 circulusd의 다음 요소를
인프로세스로 대신합니다.

| circulusd 개념 | 여기서의 대체물 |
|---|---|
| Session durable object (turn/effect program counter) | `backend/src/session.ts` 의 인메모리 durable event log + 단일 active turn |
| Runtime Revision digest | 시스템 프롬프트·모델·도구 정의의 sha256 (`agent-config.ts`) |
| Model gateway (`model` effect) | `backend/src/providers/*` — 기본은 네트워크 없는 결정적 mock, 선택적으로 pi-ai 0.84.3 실제 프로바이더 |
| Executor / MCP (`external-tool` effect) | `echo`, `now`, `calculator` 는 `backend/src/tools.ts` 의 인프로세스 도구. `python` 은 circulusd 의 **sandboxd** 를 WSL2 안에서 세션마다 하나씩 띄워 `SandboxProcessService` 로 실행 (`backend/src/sandbox/`, `sandbox/agent`) |
| Public API §36 / SSE | `backend/src/server.ts` (`POST /v1/sessions`, `POST …/turns`, `GET …/events`, abort, `Last-Event-ID` 재전송) |

엔진 자체(`LowLevelPiAgentEngine`, `createPiAgentCoreFactory`, 체크포인트 체인, effect request/settlement
digest 바인딩)는 circulusd 소스를 `link:` 의존성으로 직접 사용하며, 이 저장소에 복사본이 없습니다.

## 실행

요구사항: Node ≥ 24.1 (TypeScript 소스를 네이티브 type stripping으로 실행), pnpm 10, 옆에
클론된 `../circulusd` (의존성 설치 완료 상태).

```bash
corepack pnpm install
CIRCULUSD_TEST_MODEL=ollama:qwen3:8b corepack pnpm dev   # http://127.0.0.1:8090, 로컬 Ollama 모델
corepack pnpm dev                                        # 모델 미지정 시 네트워크 없는 mock 모델
```

환경 변수는 `.env.example` 참고. 저장소 루트에 `.env` 를 두면 `pnpm dev`/`pnpm start` 가 읽습니다(`--env-file-if-exists`). 프로바이더 스펙:

```bash
CIRCULUSD_TEST_MODEL=ollama:qwen3:8b                      # OLLAMA_HOST 또는 http://127.0.0.1:11434/v1 의 Ollama
CIRCULUSD_TEST_MODEL=ollama:qwen3:8b@http://gpu-box:11434/v1
ANTHROPIC_API_KEY=... CIRCULUSD_TEST_MODEL=anthropic:claude-sonnet-4-5
CIRCULUSD_TEST_MODEL=openai-compatible:<id>@<base-url>    # 그 밖의 OpenAI 호환 서버
```

`ollama:` 는 기동 시 Ollama 의 `/api/tags` 로 모델 존재 여부, context 길이, `tools`/`thinking` 능력을 확인합니다.
모델이 없으면 설치된 목록과 함께 종료하고, `tools` 능력이 없으면 경고 후 도구 정의를 보내지 않습니다.
thinking 을 지원하는 모델(qwen3 등)의 사고 텍스트는 `model.thinking` ephemeral 이벤트로 UI 에 흘러가며
durable 전사에는 남지 않습니다. 엔진과 무관하게 Ollama 모델의 툴 호출만 따로 확인하려면
`node backend/scripts/ollama-probe.mjs [model] [base-url]`.

## `python` 도구와 circulusd 샌드박스

모델이 `python` 도구를 호출하면 기본값(`CIRCULUSD_TEST_SANDBOX=circulusd`)에서는 circulusd 의 `sandboxd` 안에서 실행됩니다.
circulusd 의 코드는 그대로 쓰고(수정 없음), 이 저장소는 circulusd 에 아직 없는 **session host + executord 역할**만 채웁니다.

- `sandbox/bin/sandboxd`: circulusd 의 `cmd/sandboxd` 를 그대로 크로스 컴파일한 것 (`corepack pnpm sandbox:build`).
- `sandbox/agent` (Go, `sandbox/bin/sandbox-agent`): executord 대역. circulusd 가 생성한 protobuf 타입과 connect-go 클라이언트
  (`api/generated/circulus/v1alpha`, `.../circulusv1alphaconnect`)를 그대로 import 해서 sandboxd 와 대화합니다. Go 의 internal 패키지 규칙
  때문에 import 할 수 없는 `internal/sandboxrpc` 의 request digest / nonce proof 규칙만 `protocol.go` 에 그대로 옮겨 두고
  `protocol_test.go` 로 고정했습니다(`corepack pnpm sandbox:test`). 에이전트는 WSL2 안에서 돌며 다음을 합니다.
  1. 32 바이트 일회용 nonce 를 만들어 sandboxd 가 요구하는 대로 fd 3 으로 넘기고, jail 안에서 `sandboxd --backend ...` 을 띄웁니다.
  2. `ControlService.Handshake` 로 nonce 를 소비하고 nonce proof 를 검증한 뒤, 호출마다 `SandboxProcessService.Spawn` →
     (`WriteStdin`/`CloseStdin`) → `Attach` 스트림으로 stdout/stderr/exit 를 받습니다. 요청 메타와 `DispatchPermit`/`WorkspaceProtectionPermit`
     바인딩은 `internal/sandboxrpc` 가 fail-closed 로 검사하는 규칙을 따릅니다. permit 의 `value` 는 에이전트가 HMAC 으로 서명한 것이며
     state 가 발급한 것이 아닙니다(circulusd 본체에서는 executord 가 서명을 검증한 뒤 sandboxd 로 넘깁니다).
  3. 127.0.0.1 의 임시 포트에 작은 JSON API(`/v1/ready`, `/v1/run`, `/v1/sessions`)를 열고, Windows 쪽 백엔드(`backend/src/sandbox/`)는
     그것만 호출합니다. API 는 ready 라인에만 실리는 Bearer 토큰으로 보호됩니다(WSL2 는 loopback 포트를 Windows 의 모든 프로세스에
     노출하므로). nonce 는 WSL 밖으로 나가지 않습니다.
- **세션마다 sandboxd 인스턴스 하나**(jail 하나, tmpfs `/workspace` 하나). 세션 간에는 마운트/pid/net 네임스페이스와 sandboxd 자체가
  분리되어 다른 세션의 파일이나 프로세스에 닿을 수 없습니다. 첫 `python` 호출에 그 세션의 샌드박스를 띄우고(nsjail 약 0.5 초, docker 수 초),
  작업 디렉터리 `/workspace` 는 세션 안에서 호출 사이에 유지됩니다. 한 시간(`CIRCULUSD_TEST_SANDBOX_SESSION_IDLE`) 놀면 회수되고,
  동시 세션 상한(`CIRCULUSD_TEST_SANDBOX_MAX_SESSIONS`, 기본 16)을 넘으면 가장 오래 쉰 세션이 먼저 회수됩니다. 세션을
  `DELETE /v1/sessions/{id}` 하면 그 샌드박스도 내려갑니다. 회수·삭제·재기동 시 그 세션의 `/workspace` 는 사라집니다.
- sandboxd 의 idempotency 원장은 세대(generation)마다 4096 키가 상한이고 비워지지 않습니다. 에이전트는 키가 붙은 RPC(spawn, stdin,
  cancel …)를 세며 예산(기본 3800)에 닿으면, 또는 sandboxd 가 죽거나 `ResourceExhausted` 를 돌려주거나 응답을 멈추면(단항 RPC 는
  35 초에 끊김) 그 세션의 sandboxd 만 다음 세대로 다시 띄웁니다. 그 호출은 sandboxd 가 spawn 을 받아들이기 전에 실패한 경우에만
  한 번 다시 실행합니다(결과 앞에 `note:` 로 재기동과 workspace 초기화 사실이 적힘). spawn 뒤에 끊겼다면 스크립트가 이미 돌았을 수
  있으므로(`python` 의 replay 정책은 `never`) 다시 돌리지 않고 실패로 보고하며, 새 샌드박스는 다음 호출을 기다립니다.
- 기동 시 에이전트는 일회용 샌드박스를 띄워 `print('ok')` 를 실제로 돌려 보고(probe) 실패하면 종료하므로, 런처가 깨진 채로
  `python` 도구가 켜지는 일은 없습니다. 같은 때에 이전 에이전트가 비정상 종료하며 남긴 인스턴스 디렉터리(2 분 이상 지났고 제어 소켓이
  응답하지 않는 것; docker 면 그 컨테이너도)를 치웁니다. jail 감독 프로세스(nsjail/unshare)는 에이전트가 죽으면 함께 죽도록(`PDEATHSIG`)
  띄우고, 에이전트 종료 시 진행 중인 실행은 `Cancel` 로 끊습니다. 에이전트 자체가 죽으면(WSL 종료, OOM 등) 백엔드는 다음 `python`
  호출 때 에이전트를 다시 띄웁니다(30 초에 한 번까지; 모든 세션의 `/workspace` 는 사라짐). `/v1/capabilities` 의 `agentAlive`,
  `agentRelaunches` 로 확인할 수 있습니다.
- sandboxd 는 명령 매니페스트(`python3` 하나)에 있는 명령만 실행하고 제한 시간·출력 상한을 강제합니다. 턴을 중단(abort)하면
  백엔드가 에이전트 요청을 끊고 에이전트가 `Cancel` 을 보내 파이썬도 바로 죽습니다.

**launcher (`CIRCULUSD_TEST_SANDBOX_LAUNCHER`, 기본 `auto` = nsjail → docker → unshare 순으로 가능한 것):**

| launcher | sandboxd `--backend` | 격리 | 이 호스트에서 검증 |
|---|---|---|---|
| `nsjail` | `nsjail` | NsJail 이 tmpfs 루트에 `/usr` 읽기 전용 bind, user/mount/pid/net/ipc/uts 네임스페이스, uid 매핑은 newuidmap, rlimit, no_new_privs. sandboxd 는 내부 root 로 CAP_SETUID/SETGID/KILL 만 가지고, 파이썬은 `setpriv` 로 subuid 에 매핑된 uid 1000 으로 실행 | O |
| `docker` | `docker` | 세션당 컨테이너: `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 512m --user <uid>`, tmpfs `/workspace`, 이미지 기본 `python:3.14-slim`(`CIRCULUSD_TEST_SANDBOX_IMAGE`). nonce 는 컨테이너 stdin → fd 3. 제어 소켓은 `/mnt/wsl` 공유 tmpfs. **주의**: 비root `--user` 는 setuid 능력이 없어 sandboxd 와 파이썬이 같은 uid 로 돌며, 파이썬이 자기 세션의 sandboxd 를 죽이거나 제어 소켓을 건드릴 수는 있습니다(다른 세션·호스트에는 닿지 않음). 격리가 중요하면 nsjail 을 쓰세요 | O (WSL 안 docker.io 29.1.3) |
| `unshare` | `nsjail` (라벨) | util-linux `unshare` 네임스페이스 + 에이전트의 `jail-init`(mount(2)/pivot_root). nsjail 이 없을 때의 대역이며 seccomp 등은 없음 | O |

어떤 launcher 인지는 기동 로그와 `/v1/capabilities` 의 `execution.python.launcher`, UI 헤더에 항상 드러납니다. 샌드박스를 못 띄우면
`python` 도구는 **빠집니다**(호스트 실행으로 조용히 대체하지 않음). 격리 없이 호스트 파이썬으로 돌리려면 `CIRCULUSD_TEST_SANDBOX=host` 를
명시해야 하고, `off` 는 도구를 끕니다.

준비물(WSL2 Ubuntu 기준): util-linux(`unshare`, `setpriv`), `uidmap`(`newuidmap`/`newgidmap`), `/etc/subuid`·`/etc/subgid` 의 사용자 항목,
그리고 nsjail(`~/src/nsjail` 에서 빌드해 `/usr/local/bin/nsjail` 에 설치됨). docker launcher 를 쓰려면 배포판 안의 `docker` CLI
(`apt install docker.io` + docker 그룹, 또는 Docker Desktop 의 WSL 통합). Windows 쪽에는 Go 툴체인.

```bash
corepack pnpm sandbox:build      # sandboxd + sandbox-agent 를 GOOS=linux 로 빌드 → sandbox/bin/ (circulusd 저장소는 수정하지 않음)
corepack pnpm sandbox:test       # 에이전트의 프로토콜 규칙 테스트 (Go)
CIRCULUSD_TEST_SANDBOX_LAUNCHER=nsjail node --test backend/test/sandbox-live.test.ts   # 실제 sandboxd 로 라이브 테스트
```

라이브 테스트는 격리(uid, cwd `/workspace`, 호스트 파일·네트워크·환경 없음), 세션 간 workspace 분리, 제한 시간, 원장 예산에 따른
세대 재기동, abort 취소를 세 launcher 모두에서 확인합니다.

도구 자체의 동작: stdout/stderr 만 돌아오고, 기본 30 초 제한(`CIRCULUSD_TEST_PYTHON_TIMEOUT_MS`), 스트림당 16 KiB 로 잘립니다.
코드는 64 KiB, stdin 은 256 KiB 까지 받습니다(에이전트는 각각 100 KiB·1 MiB 에서 한 번 더 거절하고, 스크립트가 stdin 을 다 읽지 않고
끝나도 그 출력은 정상적으로 돌아옵니다).
작은 모델이 코드를 한 줄로 만들며 `\n` 을 문자 그대로 보내 SyntaxError 가 나면 문자열 리터럴 밖의 것만 줄바꿈으로 바꿔 한 번 재실행하고
결과 앞에 그 사실을 적습니다. mock 모델에서는 ```` ```python ```` 펜스 코드나 `python: print(2**10)` 형태가 이 도구로 라우팅되고,
UI 는 코드와 전체 출력을 접이식 블록으로 보여 줍니다.

검사와 테스트:

```bash
corepack pnpm check        # tsc (circulusd 소스까지 함께 타입 검사)
corepack pnpm test         # node --test: 도구, mock 라우팅, 엔진 end-to-end, abort, HTTP/SSE 재전송, 세션 상한/삭제 정리, 히스토리 예산
```

## API 요약

```http
GET    /v1/capabilities
POST   /v1/sessions                                  -> 201 { sessionId, runtimeRevisionDigest, … }
GET    /v1/sessions                                  -> { sessions: [{ sessionId, lastEventId, activeTurnId, turns, … }] } (요약만)
GET    /v1/sessions/{id}                             -> snapshot (turns, transcript, lastEventId)
POST   /v1/sessions/{id}/turns   Idempotency-Key: k  -> 202 { turnId }   body: {"messages":[{"role":"user","content":"…"}]}
GET    /v1/sessions/{id}/events  Last-Event-ID: n    -> text/event-stream
POST   /v1/sessions/{id}/turns/{turnId}/abort        -> 202
DELETE /v1/sessions/{id}                             -> 204
```

SSE 이벤트: `turn.accepted`, `checkpoint`, `model.started`, `model.thinking`(ephemeral), `model.delta`(ephemeral), `model.settled`,
`tool.started`, `tool.stdout`(ephemeral), `tool.completed`, `turn.completed` / `turn.failed` / `turn.aborted`.
durable 이벤트에만 `id:` 가 붙고, 재접속 시 `Last-Event-ID` 이후만 다시 보냅니다.

## 알아둘 것

- 모든 상태는 프로세스 메모리에만 있습니다. 재시작하면 세션이 사라집니다. 메모리에 두는 세션은 `CIRCULUSD_TEST_MAX_SESSIONS`(기본 200)개까지이고,
  넘치면 턴이 돌고 있지 않은 가장 오래 쉰 세션을 비웁니다(그 세션의 SSE 스트림은 끊고 python 샌드박스도 내림). 사라진 세션을 보고 있던 UI 는
  스트림이 끊기거나 turn 제출이 404 를 받으면 새 세션을 시작합니다. 세션 하나도 durable 이벤트 5000 개, 전사 400 항목까지만 유지하고
  오래된 것부터 버립니다(`stream.open` 의 `firstEventId` 가 남아 있는 가장 오래된 이벤트). 프롬프트는 64 K 자, `Idempotency-Key` 는 256 자까지입니다.
- 모델 서버가 요청을 받고 아무 것도 보내지 않으면(멈춘 Ollama, 연결을 쥐고 있는 프록시) 스트림 이벤트 없이 120 초가 지난 뒤 `MODEL_STALLED`
  로 턴을 실패시킵니다(`CIRCULUSD_TEST_MODEL_STALL_TIMEOUT_MS`). 이벤트 사이 간격을 재므로 느리지만 살아 있는 스트림은 괜찮습니다.
  SSE 클라이언트가 읽지 않아 보낼 것이 4 MB 넘게 쌓이면 그 연결을 끊습니다(브라우저는 `Last-Event-ID` 로 다시 붙음).
- circulusd Pi 어댑터는 매 턴을 빈 상태에서 시작합니다(`turn_start requires a fresh adapter state`).
  채팅처럼 보이게 하려고 이전 턴의 user/assistant 텍스트를 모델 요청 직전에 앞에 붙이며
  (`CIRCULUSD_TEST_HISTORY=0` 으로 끌 수 있음), 붙인 개수는 `model.started` 이벤트의 `historyInjected` 로 보입니다.
  붙이는 양은 모델 context window(응답 여유분과 현재 요청을 뺀 것, 4 자 ≈ 1 토큰으로 계산)에 맞춰 오래된 턴부터 잘라 냅니다.
- 엔진 자체에는 스텝 상한이 없어서, 도구를 끝없이 부르는 모델은 abort 전까지 돌았을 것입니다. 턴 하나는 도구 호출 50 회, 엔진 스텝
  1000 회를 넘으면 `TOOL_CALL_LIMIT` / `TURN_STEP_LIMIT` 으로 실패 처리됩니다(`backend/src/turn-runner.ts`).
- `echo`/`now`/`calculator` 는 백엔드 프로세스 안에서 실행됩니다. `python` 은 sandboxd 를 거치지만 dispatch permit 은 이 저장소가 만든 것이고,
  실제 durable 저장소는 관여하지 않으며, 이 프로젝트의 결과는 circulusd `docs/acceptance.md` 의 어떤 §53 항목도 승격하지 않습니다.
