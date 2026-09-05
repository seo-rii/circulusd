# circulusd 추가 검토 및 퍼징 현황 — 2026-09-05

최초 검토 기준은 `main`의 `e925065eecfef9f121c04ee0b4fb879eb0f3c94c`다. BUG-001부터 BUG-007까지의 수정 이후 추가 문제를 찾고, 로컬 Node 스크립트와 Go overlay로 재현했다. 아래 원인 분석의 줄 번호는 이 기준 커밋을 가리킨다. 후속 요청에 따라 수정과 퍼징을 추가했으며, 현재 상태와 검증 기록은 문서 끝의 **후속 수정과 퍼징 추가**에 정리한다.

## 확인한 추가 문제

| 우선순위 | ID | 문제 | 확인 범위 |
|---|---|---|---|
| P1 | BUG-008 | 지연된 GC 삭제가 재업로드 후 보호된 blob을 삭제 | 실제 디스크 FileStore + guard + 결정적 동시 실행 |
| P1 | BUG-010 | MCP 요청 수락과 취소가 겹치면 이미 받은 외부 요청 ID를 잃음 | reference Gateway + ID로 취소하는 provider fixture |
| P2 | BUG-009 | 심볼릭 링크 정규화가 복원 후 다른 파일을 가리키게 함 | 실제 파일 트리의 Scan→Materialize |
| P2 | BUG-011 | JSON 필드 대소문자 별칭이 엄격한 필드 검사를 통과 | HTTP handler와 실제 release manifest loader |
| P2 | BUG-012 | 만료된 turn의 대기 항목이 Workspace 쓰기 큐를 장시간 막음 | 실제 Workspace aggregate의 만료·복구 명령 |
| P2 | BUG-013 | 갱신된 권한으로 대기 재시도는 가능하지만 취소는 불가능 | 실제 Workspace aggregate의 권한 세대 변경 |
| P2 | BUG-014 | 배열이 재정의한 map이 CBOR 값·크기 검증을 건너뜀 | TypeScript 프로토콜 라이브러리의 프로세스 내부 입력 |

### [BUG-008] 이전 삭제 작업이 새로 보호한 blob을 지움

원인: `internal/workspace/blob/store.go:113–131`. `ValidateDeletion`과 실제 `DeleteIfMatch` 사이에 다른 작업이 진행할 수 있다. 물리 삭제 조건은 객체 incarnation이 아닌 content digest다. `internal/objectstore/file_store.go:74–76,154–177`은 실제 내용의 SHA-256을 ETag로 사용하므로 같은 내용의 재업로드는 같은 삭제 조건에 일치한다.

삭제 A가 guard 검증을 통과한 뒤 실제 파일 삭제 직전 멈추게 했다. 동일 claim의 삭제 B가 먼저 완료된 뒤 같은 바이트를 재업로드하고 새 보호 permit을 얻었다. 이 시점의 incarnation은 2다. A를 재개하면 새 객체까지 지워지고, 그 후 `CompleteDeletion`만 stale 오류를 낸다. 관찰 결과는 **guard가 Live이고 pending permit이 1개인데 Read는 NotFound**였다.

재현은 실제 `objectstore.FileStore`를 사용했다. 지연은 첫 `DeleteIfMatch` 앞의 channel gate로만 주입했다. 기존 테스트는 순차 재시도와 진입 시점부터 stale인 claim을 검사하므로 이 interleaving을 다루지 않는다. 삭제의 incarnation fence가 실제 저장소 변경까지 유효해야 한다. 단순히 마지막 상태 검사만 추가하면 이미 지운 바이트를 복구할 수 없다. ContentStore·GuardTable·object-store 조건부 삭제 계약을 함께 검토해야 하므로 `RISK_REGISTER.md`에 같은 ID로 기록했다.

### [BUG-010] MCP 수락 직후 취소 시 외부 요청 ID를 버림

원인: `internal/mcpgateway/executor.go:129–137`. `Provider.Start`가 정상 반환해도 호출 context가 취소되어 있으면 반환된 ID의 검증·저장 전에 `Cancel`로 분기한다. 취소 명령은 같은 파일 `649–655`에서 durable attempt의 ID를 사용하므로 빈 ID를 전달한다.

`ReplayNever`, invocation ledger 미지원, RPC ID로 외부 작업을 취소하는 provider로 비교했다. 첫 `Next`에서 취소하는 대조군은 요청 ID를 기록하고 전달하여 `cancelled`와 외부 작업 종료에 도달했다. `Start`가 유효한 ID와 Call을 반환하는 순간 취소하면 반환·저장 ID 모두 빈 문자열이고 상태는 `uncertain`, 외부 작업은 계속 실행됐다. `Recover`는 `interrupted`로 종료하며, cancellation lease 이후 재취소도 빈 ID를 전달했다.

이미 관찰한 수락 사실을 호출자 취소 때문에 버리지 않아야 한다. 해당 ID를 독립적인 정리 context로 먼저 보존한 뒤 취소해야 한다. 같은 패키지의 `session_dispatch.go:394–397`은 이 순서를 적용한다. 실제 외부 MCP 서버를 호출한 검사는 아니며, production adapter 부재라는 기존 STATE-007과 별개인 실행 계약 결함이다.

### [BUG-009] 심볼릭 링크의 해석 결과가 snapshot 복원 후 달라짐

원인: `internal/workspace/manifest/manifest.go:246–248`이 링크 target에 `path.Clean`을 적용한다. 실제 파일시스템은 중간 심볼릭 링크를 먼저 따라간 뒤 `..`를 처리하므로 문자열 정리와 결과가 다를 수 있다.

다음 실제 트리를 만들었다.

```text
file          = "root file"
dir/file      = "nested file"
dir/nested/
link          -> dir/nested
alias         -> link/../file
```

원래 `alias`는 `dir/file`을 읽는다. Scan은 성공하면서 target을 `file`로 바꾸고, Materialize도 성공하지만 복원된 `alias`는 root의 `file`을 읽는다. `SPEC.md:1731–1744`는 안전한 상대 symlink를 지원하며 이러한 의미 변경을 지정하지 않는다.

허용한 링크의 해석 결과를 보존하거나 안전하게 보존할 수 없는 입력을 명시적으로 거부해야 한다. 현재 경로 퍼징은 Directory만 생성하므로 이 문제를 탐색하지 못한다.

### [BUG-011] 대소문자가 다른 JSON 필드가 동일 필드로 덮어써짐

원인: `internal/platformapi/http.go:274–287,326–331`과 `internal/release/strict_json.go:56–79`. 토큰 검사는 키 문자열을 정확히 비교하지만, 후속 Go struct decoder는 대소문자가 다른 필드도 같은 struct 필드에 대응시킨다. `DisallowUnknownFields`만으로 정확한 스키마 필드명이 강제되지 않는다.

HTTP에 `content:"first"`와 `Content:"second"`를 함께 보내면 400 대신 202로 턴이 생성됐다. 같은 idempotency key로 정상 형식의 `content:"second"`만 재전송하면 200/deduplicated를 반환하여 후자의 값이 반영됐음을 확인했다. 최상위 `messages`와 `MESSAGES` 조합도 동일했다.

기존 정상 release manifest의 `"schemaVersion": 1`을 `"schemaVersion": 999, "SchemaVersion": 1`로 바꾸어도 Load와 Validate가 모두 성공했다. 실제 JSON Schema는 `schemaVersion`이 1일 것을 요구하고 미지정 필드를 금지한다(`api/json-schema/v1alpha/release-manifest.schema.json:6–11`). 이는 엄격한 스키마 검사와 실제 해석이 다른 문제다. 서명 위조나 외부 인증 우회를 재현했다는 의미는 아니다. 필드 이름과 대응 관계를 정확히 검사해야 한다.

### [BUG-012] 실행할 수 없는 대기 선두가 쓰기 큐를 막음

원인: `workers/state-app/src/workspace/aggregate.ts:566`은 acquire deadline을 turn lease 만료와 독립적으로 허용하고, `797–800`은 대기 선두 제거에 acquire deadline만 사용한다. 복구된 turn generation은 `405–410`의 queued-admission 비교에서 거부된다.

소유자의 write lease가 t501에 만료되고, 대기 선두의 turn lease는 t100에 만료되지만 acquire deadline은 t86400000인 상태를 정상 명령으로 생성했다. t502에 reconcile하여 active lease가 없어져도 뒤의 살아 있는 요청은 t503에 `write_lease_queued`, `queuePosition:2`를 반환한다. 선두는 만료된 기존 authority로 취소할 수 없고, 복구된 turn generation으로 acquire/cancel을 해도 `STALE_GENERATION`이다.

따라서 이 상태에서는 쓰기 소유자가 없어도 선두의 긴 deadline까지 후속 요청이 진행하지 못한다. 대기 기간을 유효한 수명에 맞춰 제한하거나, 현재 권한과 복구 세대를 검증하여 더 이상 실행할 수 없는 대기를 안전하게 제거하는 경로가 필요하다. 단순히 오래된 authority snapshot의 모든 만료를 현재 권한 상실로 간주해서는 안 되므로 갱신과 복구 의미를 함께 정의해야 한다.

### [BUG-013] 현재 권한으로 대기를 취소할 수 없음

원인: `workers/state-app/src/workspace/aggregate.ts:2811–2813`은 queued authority와 정확한 과거 identity 일치를 요구한다. 반면 acquire 재시도는 `authorityCanRefreshQueuedAdmission`을 통해 권한이 넓어지지 않는 새 authorization generation을 허용한다.

generation 11로 대기한 뒤 동일 permissions의 generation 12 및 새 emergency overlay를 제출했다. acquire 재시도는 성공적으로 `write_lease_queued`를 반환하지만 저장된 queue authority는 11로 남는다. 같은 generation 12로 cancel하면 `STALE_GENERATION`, 과거 generation 11로 cancel하면 성공했다. 실제 ingress가 새 권한만 발급하는 상황에서는 더 이상 사용할 수 없는 과거 권한을 취소에 요구하게 된다.

취소에도 최신 권한의 검증과 안정적인 요청 identity 비교를 적용해야 한다. BUG-012의 deadline 정리와는 원인 및 수정 위치가 다르다.

### [BUG-014] 배열의 사용자 정의 map이 CBOR 정규화를 건너뜀

원인: `packages/protocol-types/src/cbor.ts:91–114`. 배열의 own property는 검사하지만 custom prototype은 거부하지 않고 `value.map()`을 호출한다.

```js
class Values extends Array {
  map() { return [Number.MAX_SAFE_INTEGER + 1]; }
}
encodeCanonicalCbor(Values.of(0), { maxDepth: 0, maxItems: 1 });
```

실제 encoder 출력은 `811b0020000000000000`이다. 일반 `[0]`는 같은 depth/item 제한에서 거부되지만 위 배열은 허용되며, 출력은 같은 패키지의 decoder가 unsafe integer로 거부한다. 정규화 함수가 자신이 검증하지 않은 배열을 반환한 결과다.

검증 범위는 프로세스 내부 확장·런타임 값이다. 원격 CBOR decoder나 SessionHost의 별도 prototype 검사까지 통과하는 경로는 확인하지 않았다. 일반 배열만 허용하고 입력 배열의 재정의 가능한 메서드 대신 검증한 index/data descriptor를 직접 순회해야 한다.

## 최초 검토 당시 퍼징 현황과 실제 실행

**최초 검토 당시 Go 네이티브 퍼징 타깃은 5개였다.** 일반 `go test`는 등록된 seed corpus를 검사하며, 입력 변형을 수행하는 퍼징은 `-fuzz`로 따로 실행해야 한다. 이번에는 다섯 타깃을 각각 `-fuzztime=30s -parallel=2`로 실행했다. 총 2,232,950회 실행에서 실패 입력은 발견되지 않았고 모두 종료 코드 0이었다. 제한된 시간의 실행 결과이며 전체 결함 부재를 보장하지 않는다.

| 타깃 | 위치 | 검사하는 성질 | 실행 수 |
|---|---|---|---:|
| `FuzzDecodeCanonical` | `internal/canonical/fuzz_test.go:58` | 잘못된 CBOR의 panic 방지, 받아들인 bytes의 왕복·정규성·digest 결정성 | 678,795 |
| `FuzzParseIdentity` | `internal/identity/fuzz_test.go:41` | ID 파싱·종류 구분·원문 보존·재파싱 | 712,474 |
| `FuzzVerifyNonceProof` | `internal/handshake/proof_fuzz_test.go:16` | 정상 proof 수락, 변조·다른 nonce·길이 오류 거부 | 295,554 |
| `FuzzCanonicalizePathSafety` | `internal/workspace/manifest/canonicalize_fuzz_test.go:17` | 경로 안전성·정렬·정규화 멱등성 | 119,953 |
| `FuzzDecodeStrictJSON` | `internal/release/strict_json_fuzz_test.go:17` | panic 방지와 기본 JSON decoder가 거부하는 입력의 수락 방지 | 426,174 |

최초 검토 당시 확인한 공백은 다음과 같다.

- 저장소에 퍼징을 주기적으로 실행하는 CI 설정이나 전용 runner가 없다. 저장소 밖의 CI 실행 여부는 확인하지 않았다.
- TypeScript에는 fuzz/property framework나 무작위 generator가 없고, ordering 테스트의 24/32회 반복 및 fault matrix는 고정된 결정적 사례다.
- 경로 퍼징은 모든 entry를 Directory로 생성한다(`canonicalize_fuzz_test.go:37–42`). Symlink target·symlink graph·실제 Scan→Materialize 의미 보존을 검사하지 않는다.
- release JSON 퍼징은 strict decoder의 성공 후 기본 decoder도 성공하는지만 검사한다(`strict_json_fuzz_test.go:38–45`). 키 중복·대소문자 별칭·미지정 필드를 반드시 거부하는지는 독립된 assertion이 없다. strict 단계가 없어져도 이 성질만으로는 이를 탐지할 수 없다.
- 삭제→동일 내용 재업로드→보호, provider 수락→취소→수락 기록, 권한 갱신→대기 취소 등 **작업 순서와 시간·세대를 함께 변형하는 퍼징**이 없다. Go/TypeScript CBOR 구현 사이의 무작위 differential 검사도 찾지 못했다.

검토 당시에는 BUG-008/010의 실행 순서와 BUG-012/013의 만료·세대 변경을 포함하는 상태 기반 퍼징, symlink 트리의 왕복 성질, Go/TS canonical bytes·거부 조건의 differential 검사 순으로 진행할 것을 권장했다.

재현 가능한 기존 퍼징 실행 예:

```bash
go test ./internal/canonical -run='^$' \
  -fuzz='^FuzzDecodeCanonical$' -fuzztime=30s -parallel=2
```

## 최초 재현 실행 기록

| 작업 | PID | 종료 코드와 의미 | 로그 |
|---|---:|---|---|
| 기존 Go 퍼징 5개, 각각 30초 | 1721182 | 모두 0, 실패 입력 미발견 | `/home/seorii/logs/circulusd-review-more-20260905-fuzz-_wuyemiq.log` |
| BUG-008/009 실제 workspace 재현, race 검사 | 1777790 | 1, 객체·symlink 보존 assertion이 결함을 탐지 | `/home/seorii/logs/circulusd-workspace-review-4bc40633899b45a0a0070955e8488582.log` |
| BUG-010 MCP 취소 비교 | 1830852 | 0, 결함 관찰값을 assertion | `/home/seorii/logs/circulusd-review2-gateway-final-fhgrlmhx.log` |
| BUG-011 HTTP/release JSON 재현 | 1777109 | 1, 모호한 입력 거부 assertion이 결함을 탐지 | `/home/seorii/logs/circulusd-review-more-20260905-json-repro-i0ditjo4.log` |
| BUG-012/013/014 TypeScript 재현 재확인 | 2106068 | 0, 결함 관찰값을 assertion | `/home/seorii/logs/circulusd-review-more-20260905-typescript-repro-t89euti5.log` |

임시 재현은 다음 명령으로 다시 실행할 수 있다. `/tmp` 자료의 수명은 이 호스트의 보존 기간에 따른다.

```bash
go test -race -overlay /tmp/circulusd-workspace-review-g_o1p3zo/overlay.json \
  ./internal/workspace/blob ./internal/workspace/materialized \
  -run '^TestReview' -v -count=1 -timeout=30s
go test -overlay /tmp/circulusd-gateway-review2-k8t29t2x/overlay.json \
  ./internal/mcpgateway -run '^TestReviewCancellationRetainsReturnedProviderIdentity$' -count=1 -v
go test -overlay /tmp/circulusd-review-more-json-20260905-s6yqiclm/overlay.json \
  ./internal/platformapi ./internal/release -run '^TestReviewMore' -count=1 -v
node --disable-warning=ExperimentalWarning /tmp/circulusd-ts-audit-20260905.mjs
```


## 후속 수정과 퍼징 추가

| ID | 현재 상태 | 수정과 검증 범위 |
|---|---|---|
| BUG-008 | 수정 완료 | 공유 GuardTable의 객체별 잠금이 물리 업로드·보호·삭제와 guard 변경을 함께 보호한다. 실제 FileStore와 두 ContentStore로 지연 삭제, dedup 도중 삭제, 취소, 다른 digest의 진행을 검사한다. |
| BUG-009 | 수정 완료 | 내부 dot·parent·trailing slash를 보존하고 symlink 그래프를 따라 root 이탈과 40회 초과 expansion을 거부한다. 실제 파일·디렉터리·ENOENT·ENOTDIR 결과를 Scan→Materialize 전후 비교한다. |
| BUG-010 | 수정 완료 | Start가 반환한 유효한 provider ID를 기존 bounded 독립 context로 저장한 뒤 취소한다. 취소 7시점, Start 오류, Call 부재, 잘못된 ID, 중복 dispatch 방지를 검사한다. |
| BUG-011 | 수정 완료 | HTTP와 release loader가 공통 `internal/strictjson`으로 정확한 JSON 필드 이름과 중복·trailing data를 검증한다. map 키는 데이터로 보존하며, HTTP의 UTF-8·surrogate 검사는 유지한다. |
| BUG-012 | 미수정 | 대기열 만료 수정 작업을 맡긴 하위 에이전트 실행이 자동 안전 검토에서 차단됐다. |
| BUG-013 | 미수정 | 같은 실행에 포함된 권한 갱신 수정도 차단됐다. |
| BUG-014 | 수정 완료 | 일반 배열만 허용하고 검증한 index/data descriptor를 순회한다. 재정의된 map/iterator/getter를 호출하지 않는다. 파생 RPC 해시, Go client 상수, 공유 golden, workerd bundle도 갱신했다. |

BUG-012/013 실행은 `possible cybersecurity risk`라는 응답과 함께 종료됐다. 차단된 작업을 다른 에이전트나 실행 경로로 재시도하지 않았다. 이 응답은 해당 두 작업이 완료되지 못한 이유이며, 프로젝트 자체의 정책 위반을 입증하는 자료는 아니다. 두 문제의 기존 재현과 미수정 상태를 보존한다. BUG-009 담당 에이전트도 수정 코드 저장과 검사 시작 후 같은 응답으로 중단됐으나, 이미 시작된 30초 퍼징은 1,595회·종료 코드 0으로 끝났다. 재시도 없이 저장된 결과와 별도로 이미 시작한 전체 검사 결과를 확인했다.

BUG-008의 잠금은 **같은 프로세스에서 동일 GuardTable을 공유하는 ContentStore**에 적용된다. 직접 object-store 변경이나 별도 프로세스의 구현에는 그 저장소 경계에 맞는 동등한 장치가 필요하다. 기존 DATA-001 외부 저장소 qualification을 완료한 것으로 간주하지 않는다.

퍼징 도구의 사용법은 [fuzzing.md](fuzzing.md)에 있다. `pnpm fuzz:list`는 실제 소스의 타깃을 발견하고, 아래 명령은 시간과 동시 작업 수를 제한한 백그라운드 실행을 시작한다.

```sh
pnpm fuzz --duration 30s --workers 2 --seed 20260905 --num-runs 5000
```

명령이 출력한 `status.json`의 `state: "finished"`와 `exit_code`가 최종 결과다. 로그와 최소 반례를 보존하며, Go corpus 또는 fast-check seed/path로 실패를 재현할 수 있다. TypeScript에는 `fast-check@4.9.0`을 고정했다.

네이티브 Go 타깃은 기존 5개에서 **9개**로 늘었다. 추가한 성질은 다음과 같다.

- `FuzzContentStoreIncarnationOrders`: 실제 FileStore의 삭제·재업로드·보호·finalize·abandon·Sweep 순서를 변형하고 pending permit의 바이트 보존을 확인한다.
- `FuzzProviderAcceptanceCancellation`: 수락·취소 순서와 provider 응답을 변형하고 유효한 ID의 영속 보존 및 중복 dispatch 방지를 확인한다.
- `FuzzSymlinkScanMaterialize`: 제한된 실제 디렉터리·symlink 그래프를 생성하고 kernel `openat2`를 독립 기준으로 사용하여 파일 내용, 종류, 경로 오류와 snapshot digest 보존을 검사한다.
- `FuzzStrictJSONFieldNames`: 정상 필드와 escaped 정상 필드는 수락하고, 중복·대소문자 별칭·미지정 필드는 반드시 거부한다. 기존 raw JSON 퍼징도 디코딩 결과 일치를 검사하도록 강화했다.
- TypeScript CBOR 속성 4개: 생성 트리의 왕복, 임의 bytes의 정확한 재인코딩, encode/decode의 크기·깊이·item 한도 일치, 사용자 정의 배열 메서드 미실행.
- Go/TypeScript differential 속성 2개: 생성 값과 임의·변형 bytes에 동일한 명시적 한도를 적용하여 수락 여부와 canonical bytes를 비교한다.

실행 도구 자체도 잘못된 probe를 주입하여 실패 검출·최소 반례 저장·동일 seed/path 재현을 확인했다. SIGTERM 후 자식 프로세스 종료와 최종 상태 130 보존도 검사했다. 이 검증 wrapper는 PID 2417156, 종료 코드 0이며 로그는 `/home/seorii/logs/circulusd-fixes-20260905-fuzz-tooling-verify-vddh_lff.log`다.

### 후속 검증 기록

| 검사 | PID | 종료 코드 | 로그 또는 상태 파일 |
|---|---:|---|---|
| BUG-008 race / 20초 퍼징 1,774회 | 2488059 / 2488060 | 각각 0 | `/home/seorii/logs/circulusd-bug008-race-c89377100d2649c5910c2af7e4e34a3d.log`, `/home/seorii/logs/circulusd-bug008-fuzz-3efb03f9ff2b42ed9e486b09e9356627.log` |
| BUG-009 race / 30초 퍼징 1,595회 | 2547145 / 2561246 | 각각 0 | `/home/seorii/logs/circulusd-bug009-race-j7se3ri0.log`, `/home/seorii/logs/circulusd-bug009-fuzz-op9mbh9h.log` |
| BUG-010 race / 30초 퍼징 20,975회 | 2240053 / 2246718 | 각각 0 | `/home/seorii/logs/circulusd-bug010-race-hc0ogogt.log`, `/home/seorii/logs/circulusd-bug010-fuzz-or0ou3pn.log` |
| BUG-011 관련 Go 패키지 race | 2378798 | 0 | `/home/seorii/logs/circulusd-fuzz-fixes-20260905-json-green-8eddek0o.log` |
| JSON 필드명 30초 퍼징 72,904회 + TS 속성 기본 실행 | 2373175 | 각각 0 | `/home/seorii/logs/circulusd-fuzz-fixes-20260905-json-cbor-fuzz-p9srg53l.log` |
| TypeScript 속성 20,000회 + differential 10,000회 + canonical Go 1초 | 2444470 | 0 | `/home/seorii/logs/circulusd-fuzz-pgfj1s2e/status.json` |
| differential seed 42 추가 20,000회 | 2383103 | 0 | `/home/seorii/logs/circulusd-fuzz-0p5bpji0/status.json` |
| `pnpm test` 541개, `pnpm check`, `pnpm lint` | 2497009 | 각각 0 | `/home/seorii/logs/circulusd-fuzz-fixes-20260905-typescript-final2-g05vztcd.log` |
| API 계약 checker 및 Python unittest | 2427244 | 각각 0 | `/home/seorii/logs/circulusd-fuzz-fixes-20260905-contracts-final-55x1b104.log` |
| `go test -race -p=2 ./...` 52개 패키지 및 `go vet ./...` | 2566742 | 각각 0 | `/home/seorii/logs/circulusd-fuzz-fixes-20260905-go-final-u3i53jjb.log` |
| 최종 통합 퍼징: Go 타깃별 10초, TS/differential 속성별 5,000회 | 2566750 | 모든 job 0 | `/home/seorii/logs/circulusd-fuzz-r69e6dak/status.json` |
| 실제 stock workerd fixture | 2497016 | 0 | `/home/seorii/logs/circulusd-fuzz-fixes-20260905-workerd-final-6a9lhilq.log` |

JSON·CBOR의 영구 회귀는 수정 전 코드에서 예상대로 실패했다(PID 2317415, `/home/seorii/logs/circulusd-fuzz-fixes-20260905-json-cbor-red-3m56m35r.log`). BUG-008도 수정 전 회귀와 fuzz seed가 보호된 객체 유실을 탐지했다.

실제 workerd 검사는 버전 `workerd 2026-08-25`와 바이너리 SHA-256 `b805ed481caa643953357d38146b82c118addcb525eb87e3d190b5617c82bc75`를 고정했다. 갱신한 Pi bundle의 SHA-256은 `52369d7290d083ce102306315793f416404d6fcd96abbca9d0007ae0cb790527`이며 두 content-addressed Worker 참조와 일치한다. 모델/MCP broker는 fixture이며 별도의 CPU/RSS·shard 외부 qualification은 기존과 같이 `NOT_RUN`이다.


최종 통합 실행은 다음 명령을 사용했다. 9개 Go 타깃에서 총 **963,381회**, TypeScript 속성 4개에서 **20,000회**, Go/TS differential 속성 2개에서 **10,000회**가 통과했다. Linux filesystem 타깃도 포함되며, 고정 seed는 `20260905`다.

```sh
pnpm fuzz --duration 10s --workers 2 --seed 20260905 --num-runs 5000
```

| 최종 native 타깃 | 실행 수 | 로그 |
|---|---:|---|
| `FuzzDecodeCanonical` | 215,998 | `/home/seorii/logs/circulusd-fuzz-r69e6dak/00.log` |
| `FuzzVerifyNonceProof` | 118,178 | `/home/seorii/logs/circulusd-fuzz-r69e6dak/01.log` |
| `FuzzParseIdentity` | 365,021 | `/home/seorii/logs/circulusd-fuzz-r69e6dak/02.log` |
| `FuzzProviderAcceptanceCancellation` | 4,478 | `/home/seorii/logs/circulusd-fuzz-r69e6dak/03.log` |
| `FuzzDecodeStrictJSON` | 206,414 | `/home/seorii/logs/circulusd-fuzz-r69e6dak/04.log` |
| `FuzzStrictJSONFieldNames` | 28,951 | `/home/seorii/logs/circulusd-fuzz-r69e6dak/05.log` |
| `FuzzContentStoreIncarnationOrders` | 825 | `/home/seorii/logs/circulusd-fuzz-r69e6dak/06.log` |
| `FuzzCanonicalizePathSafety` | 22,877 | `/home/seorii/logs/circulusd-fuzz-r69e6dak/07.log` |
| `FuzzSymlinkScanMaterialize` | 639 | `/home/seorii/logs/circulusd-fuzz-r69e6dak/08.log` |
