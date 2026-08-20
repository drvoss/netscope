# NetScope 동작 계약 스펙 (Behavioral Contract) v1

> 이 문서는 Go와 C++ 구현의 **관측 가능한 동작이 어떻게 동일해야 하는지**를 정의하는 공개 계약이다.
>
> 여기 적힌 상수·열거형·계산식은 두 구현이 **문자 그대로** 공유한다. 한쪽만 바꾸는 것은 버그다.
> 아래 제약은 양쪽 구현과 회귀 테스트에서 함께 확인한다.

---

## 0. 툴체인 요구사항 (실측값)

| 구현 | 요구사항 | 비고 |
|------|----------|------|
| Go | **1.25.0+** | `go.mod` 값. `golang.org/x/net`·`x/sys`·`x/text` 최신 릴리스가 요구한다. 기획안 §5.1 의 "1.22+" 는 구현 전 추정치로 실제 의존성 조합에서는 성립하지 않는다 |
| C++ | C++20 | MSVC 14.51+ 확인 · clang(Zig 번들) 로 glibc/musl 타깃 확인 |
| C++ 의존성 | FTXUI 7.0.0 · Asio 1.32(standalone) · doctest 2.5.3 | vcpkg manifest |

`std::atomic<std::shared_ptr<T>>` 는 **쓰지 않는다.** C++20 표준에는 있으나 libc++ 가 미구현이어서
libc++ 기반 플랫폼에서 컴파일이 깨진다. mutex 로 보호된 `shared_ptr` 를 쓴다.

---

## 1. 용어

| 용어 | 정의 |
|------|------|
| **target** | 사용자가 지정한 최종 목적지. 모든 프로브는 *언제나* 이 주소로 보낸다. |
| **probe** | `{generation, family, ttl, attempt, sentAt}` 로 식별되는 1회 시도. 목적지는 항상 target, **TTL 만 변한다**. |
| **responder** | 어떤 TTL 의 프로브에 응답한 IP. *관측 결과*이며 프로브의 목적지가 아니다. |
| **hop position** | TTL 값 하나에 대응하는 버킷. 0개 이상의 responder 를 가진다(ECMP). |
| **generation** | target 변경 / 재프로브(`r`) 마다 1 증가. 이전 generation 의 결과는 **버린다**. |
| **snapshot** | UI 가 읽는 불변 상태. 단조 증가 `revision` 을 가진다. |

> **중요 — 계획서 §2 문구 정정.** 계획서는 "각 홉마다 주기적으로 ping" 이라 서술하지만, 실제 측정은
> **target 으로 향하는 TTL 제한 프로브**여야 한다. 라우터 인터페이스 주소로 직접 ping 하면 다른
> 순/역방향 경로와 다른 control-plane 정책을 재게 되어 경로상 지연과 다른 값이 나온다
> (cross-review R1-2, codex Critical). mtr 도 TTL 제한 프로브를 쓴다.

---

## 2. 데이터 모델

두 언어가 동일한 필드명·의미를 갖는다. JSON 직렬화 시의 키는 아래 백틱 이름을 쓴다(parity 비교용).

```
Snapshot
  revision        uint64      단조 증가
  generation      uint64
  target          Target
  startedAt       ts          엔진 기동 시각(uptime 계산용)
  mode            ProbeMode   raw | helper | command
  degraded        bool        mode==command 이면 true
  paused          bool
  hops            []HopPosition   ttl 오름차순, 빈틈 없음
  local           LocalInfo
  health          Health
  events          []Event     최신순, 최대 200개 보관
  cadence         Cadence     실제 적용된 케이던스(§4.4)

Target
  input           string      사용자 입력 원문
  ip              string      선택된 IP (표시용 정규화)
  family          "ip4"|"ip6"
  resolvedAt      ts

HopPosition
  ttl             int
  status          HopStatus   §5
  sent            uint64      이 TTL 로 보낸 프로브 수 (창 무관 누적)
  replied         uint64      응답 받은 프로브 수 (창 무관 누적)
  lossPct         float       창 기준 손실률, §4.2
  responders      []Responder 관측 횟수 내림차순, 동률이면 IP 오름차순
  primary         string      responders[0].ip 또는 ""
  stats           RttStats    primary responder 의 창 통계, §4
  isDestination   bool        Echo Reply 를 받은 TTL

Responder
  ip              string
  rdns            string      "" = 미조회, "-" = 조회했으나 없음
  asn             string      "AS15133" 형식, "" = 미조회, "-" = 없음
  org             string
  seen            uint64      이 responder 가 응답한 횟수
  firstSeenAt     ts
  lastSeenAt      ts
  stats           RttStats    responder 별 독립 창 (혼합 금지)

RttStats
  samples         int         창 안의 성공 샘플 수
  lastMs          float?      null = 없음
  bestMs          float?
  avgMs           float?
  worstMs         float?
  jitterMs        float?      MASD, §4.3. 유효 인접쌍 <2 이면 null
  stdevMs         float?      표본표준편차, §4.3. samples<2 이면 null
  spark           []float     스파크라인용 창 내 RTT 시계열 (최대 120)

Event
  at              ts
  kind            EventKind   §5.4
  ttl             int?
  text            string      표시 문구 (양 구현 동일 포맷)
```

---

## 3. 동시성 계약

### 3.1 단일 writer

```
   [probe workers] ──ProbeResult(불변)──▶ ┐
   [enrich workers]──EnrichResult(불변)──▶ ├─▶ [engine loop] ──▶ Snapshot(불변) ──▶ [UI]
   [UI keypress]  ────Command───────────▶ ┘         (유일한 mutator)
```

- 워커는 **공유 상태를 절대 수정하지 않는다.** 값만 반환한다.
- 엔진 루프만 `HopPosition` / `Responder` / 통계 / 이벤트를 변경한다.
- UI 는 `shared_ptr<const Snapshot>` / `*Snapshot` 을 읽기만 한다. 역방향은 Command 채널뿐이다.
- `generation` 이 현재와 다른 `ProbeResult` 는 **조용히 버린다**.

| | Go | C++ |
|---|---|---|
| 결과 수집 | `chan ProbeResult` (버퍼 256) | `BlockingQueue<ProbeResult>` |
| 명령 | `chan Command` (버퍼 16) | `BlockingQueue<Command>` |
| 스냅샷 배포 | **capacity-1 병합 채널** — 가득 차면 이전 것을 버리고 최신으로 교체 | `std::atomic<std::shared_ptr<const Snapshot>>` 교체 + `PostEvent` 로 "새 버전 있음" 신호만 |
| UI 갱신 | `tea.Tick` 100ms + 스냅샷 수신 | `PostEvent` 수신 시 최신 shared_ptr 읽기 |

느린 터미널이 스냅샷을 적재하지 못하게 **반드시 병합(coalescing)** 한다. (R1-1 #2)

### 3.2 UI 갱신 주기

렌더는 최대 **10 Hz**. 그보다 자주 스냅샷이 생겨도 UI 는 최신 것만 그린다.

### 3.3 종료 프로토콜 (순서 고정)

3자 리뷰가 모두 최대 위험으로 지목한 부분. **아래 순서를 어기면 크래시한다.**

1. UI 명령 수신 중단, `generation` 무효화 → 신규 프로브 발행 금지
2. 워커에 stop 요청 (`context.Cancel` / `stop_token`)
3. **소켓·ICMP 핸들·타이머·자식 프로세스를 명시적으로 닫는다.**
   `stop_token` 만으로는 블로킹 `recv` 가 깨지지 않는다 (R1-1 #3)
4. 미완료 프로브 드레인 — 상한 `probeTimeout + 1s`. 넘으면 포기
5. `PostEvent` 게이트를 닫는다 (lifetime token). 이후 Post 시도는 no-op
6. 모든 워커 join / `WaitGroup.Wait()`
7. 그 다음에야 엔진 상태와 `ScreenInteractive` 를 파괴

C++ 추가 규칙: 비동기 `IcmpSendEcho2` 는 **호출당 전용 reply buffer + 이벤트 컨텍스트**를 가지며,
완료(또는 취소 확인)까지 그 버퍼가 살아 있어야 한다. 핸들을 먼저 닫고 버퍼를 해제하면 use-after-free.

---

## 4. 측정 수치 계약

### 4.1 시간과 창

| 상수 | 값 | 비고 |
|------|-----|------|
| `windowDuration` | **120 s** | 시간 기반 창. 샘플 수 기반 금지 — 케이던스가 홉마다 달라 대표 시간이 달라진다 (R1-4) |
| `windowMaxSamples` | **120** | 창 안 샘플 상한(메모리 고정). 초과 시 가장 오래된 것 폐기 |
| `probeTimeout` | **1500 ms** | 이 시간 내 응답 없으면 `Timeout` |
| 시계 | **monotonic clock** | RTT 측정에 벽시계 사용 금지 |
| RTT 소스 | 애플리케이션 왕복 측정(송신→수신 monotonic 차) | Windows `RoundTripTime`(ms 정수)는 참고만. 두 구현이 같은 방식을 쓰기 위함 |
| 반올림 | 표시 시 소수 1자리, 계산은 float64 | |

### 4.2 손실률

```
lossPct = 100 * (창 안 timeout 수) / (창 안 sent 수)
```

- 분모는 **해당 TTL 로 보낸 프로브**만. 다른 TTL 과 섞지 않는다.
- 창 안 `sent == 0` 이면 `lossPct = null` → UI 는 `---`
- **`Timeout` 만 손실로 센다.** `TTLExpired` 와 `Reply` 는 응답이다.
  `Unreachable`(ICMP type 3) 은 응답으로 세고 이벤트를 남긴다 — 손실이 아니다.
- 태어나서 한 번도 응답이 없는 홉의 100% 는 "손실" 이 아니라 "무응답" 이다. §5 상태로 구분해 표시한다.

### 4.3 지터와 표준편차

```
jitterMs (MASD) = mean( |rtt[i] - rtt[i-1]| )
```

- **인접 성공 프로브 쌍만** 포함한다. 중간에 `Timeout` 이 1회라도 끼면 그 쌍은 **끊긴다**.
  (손실을 지터에 이중 계산하지 않기 위함 — 3자 모두 동일 지적)
- 유효 인접쌍 < 2 → `jitterMs = null` → UI 는 `—`. **0 으로 표시하지 않는다.**
- 손실 구간을 timeout 값으로 메워서 차분하지 않는다.
- `stdevMs` = 창 안 성공 샘플의 **표본**표준편차(n-1). `samples < 2` → null.
- 표의 `JIT` 컬럼 = `jitterMs`. 선택 홉 상세 패널에 `StDev` 를 함께 표시. (이견 해소, R1-3)
- RFC 3550 평활 추정기는 **쓰지 않는다** — RTP 수신기용 신호로 의미가 다르다.

### 4.4 케이던스와 패킷 예산

| 항목 | 값 |
|------|-----|
| 목적지 TTL | **1 probe / 1 s** |
| 중간 TTL | **1 probe / 4 s** |
| TTL 당 동시 미완료 프로브 | **1개** (이전 것이 끝나거나 timeout 되기 전엔 다음을 보내지 않음) |
| 전역 상한 | **10 probes / s** (재추적 sweep 포함) |
| 스케줄 지터 | 각 발행에 `±20%` 랜덤 오프셋 — 버스트 방지 |
| trace sweep | 별도 예산, 동시 **최대 4 TTL**, 라운드 간 최소 30 s |

홉 수 × 케이던스가 전역 상한을 넘으면 **중간 홉부터** 주기를 늘려 희석한다(목적지 우선).
적용된 실제 값은 `Snapshot.cadence` 에 실어 UI 에 표시한다 — 두 구현이 같은 수를 보여야 한다.

---

## 5. 홉 상태 분류

### 5.1 상태 열거형

이진 `FILTERED`/`LOSS` 는 **폐기**했다. 무응답은 필터링을 증명하지 못한다 (R1-1 #5).

| 상태 | 조건 | UI 표기 |
|------|------|---------|
| `UNKNOWN` | 이 TTL 로 아직 `minSamples`(=3) 미만 전송 | `···` |
| `RESPONDING` | 창 안에 응답 ≥1 | 통계 정상 표시 |
| `SILENT` | 누적 응답 0, 그리고 더 큰 TTL 도 응답 없음 | `* (no reply)` |
| `TRANSIT_ONLY` | 누적 응답 0, 그러나 **더 큰 TTL 이 응답함** → 트래픽은 통과시키지만 프로브에 답하지 않음 | `* (transit ok)` |
| `DEGRADED` | 이전에 `RESPONDING` 이었고, 연속 `lossStreak`(=4) 회 timeout | 손실률 강조 |

- **"filtered" 라고 단정하지 않는다.** `TRANSIT_ONLY` 는 관측 사실("통과는 되나 응답 안 함")만 말한다.
  ICMP rate-limit / ACL / control-plane 과부하 / MPLS / 미관측 ECMP 분기를 구분할 수 없기 때문이다.
- 명시적 ICMP Unreachable(type 3)을 받은 경우에만 `Unreachable` 이벤트로 사유를 표시한다.
- **중간 홉에 전달 손실을 귀속시키지 않는다.** 손실 증가가 목적지를 포함한 *모든* 하위 TTL 에서
  지속될 때만 로그에 `possible loss after hop N` 을 남긴다.

### 5.2 히스테리시스 상수

| 상수 | 값 |
|------|-----|
| `minSamples` | 3 |
| `lossStreak` | 4 (연속 timeout → `DEGRADED`) |
| `recoverStreak` | 2 (연속 응답 → `RESPONDING` 복귀) |

### 5.3 경로 변경 감지

홉 배열 단순 비교는 ECMP churn 으로 오탐이 폭주한다. 대신:

1. TTL 별 **responder 집합**을 비교한다 (순서 무시).
2. 변화가 **연속 2 trace 라운드** 지속될 때만 이벤트를 낸다 (디바운스).
3. 변화 종류를 구분한다: `responder-set change` / `path-length change` / `destination change` /
   `temporary silence`(이벤트 미발생).
4. 한 TTL 에서 responder 가 바뀌면 **그 responder 의 통계 창을 새로 시작**한다.
   서로 다른 라우터의 RTT 를 섞으면 avg/jitter 가 허상이 된다.

### 5.4 이벤트 종류

`start` `resolved` `trace-round` `route-change` `responder-change` `unreachable` `timeout-streak`
`degraded-mode` `permission` `target-change` `paused` `resumed` `enrich` `health` `error`

표시 문구는 두 구현이 동일 포맷을 쓴다: `HH:MM:SS <text>`.

---

## 6. 플랫폼 백엔드

### 6.1 백엔드 인터페이스 (양 언어 동일 계약)

```
ProbeOutcome = Reply | TTLExpired | Unreachable | Timeout | PermissionDenied | BackendError
ProbeResult  = { generation, ttl, attempt, outcome, responderIP, rttMs, sentAt, recvAt, note }
```

백엔드는 이 값만 만들어 낸다. 분류·집계는 엔진 몫이다.

### 6.2 백엔드 선택 (capability detection)

**플랫폼별 후보 목록은 두 구현이 동일하다.** 순서도, 항목도 같다.

| 플랫폼 | 순위 | mode | 구현 | 비고 |
|--------|------|------|------|------|
| **Windows** | 1 | `helper` | IP Helper `IcmpSendEcho` + `IP_OPTION_INFORMATION.Ttl` | **IPv4 전용** |
| | 2 | `command` | `tracert` / `ping` 파싱 | **degraded**. Windows IPv6 는 여기로 떨어진다 |
| **POSIX** | 1 | `raw` | ICMP datagram 소켓(`SOCK_DGRAM`) + `IP_TTL`/`IPV6_UNICAST_HOPS` | `net.ipv4.ping_group_range` 허용 시 비권한 동작. **아래 강화 판정을 통과해야 채택** |
| | 2 | `raw` | raw 소켓(`SOCK_RAW`) + `IP_TTL`/`IPV6_UNICAST_HOPS` | root 또는 `cap_net_raw` 필요 |
| | 3 | `command` | `traceroute` / `ping` 파싱 | **degraded** |

> **Windows 에서 raw ICMP 소켓을 후보에 넣지 않는 이유** (실측 근거):
> Windows raw ICMP 소켓은 Echo Reply 는 받지만 중간 라우터가 보내는 **Time Exceeded 를 소켓에 전달하지 않는다.**
> 이 저장소를 만들며 확인: raw 모드로 `1.1.1.1` 을 추적하면 홉 1~4 가 전부 무응답으로 잡히고 목적지만 응답했다.
> 경로 표가 "네트워크가 고장난 것처럼" 보이므로, 없는 것보다 나쁘다. `IcmpSendEcho` 는
> `IP_TTL_EXPIRED_TRANSIT` 로 TTL 만료를 응답 라우터 주소와 함께 명시적으로 알려준다.
> Go 는 cgo 없이 `golang.org/x/sys/windows` 로 이 API 를 호출하므로 순수 Go 빌드가 유지된다.

**동시성 있는 두 프로세스**: raw 소켓(POSIX `SOCK_RAW`)은 호스트의 모든 ICMP 패킷을 보므로
**ICMP identifier 와 sequence 를 모두 검증한다.** sequence 는 프로세스마다 1부터 시작하므로 단독으로는
충돌한다. ICMP datagram 소켓은 커널이 demultiplex 하고 identifier 를 덮어쓰므로 identifier 를 **무시**한다.

기동 시 1회 탐지하고 `Snapshot.mode` 에 실어 헤더에 표시한다.
탐지는 **실제 프로브 1발(TTL=1, generation 0)을 보내서** 확인한다 — Windows 에서는 소켓이 열려도 모든
송신이 실패할 수 있어 "생성자가 성공했다"는 것이 동작 근거가 되지 못한다.

**판정 규칙 (두 구현 동일. C++ `verifyBackend()`, Go `verify()`)**:

| 후보 | 보내는 프로브 | `PermissionDenied` / `BackendError` | `Timeout` | `Reply` / `TTLExpired` / `Unreachable` |
|------|------|:---:|:---:|:---:|
| 대부분 (`helper`, POSIX `SOCK_RAW`) | TTL 1, 1발 | 기각 | **채택** | 채택 |
| POSIX ICMP **datagram** 소켓 | TTL 1..3, 응답을 관측하면 즉시 중단 | 기각 (즉시) | 다음 TTL 로 | **채택** (즉시) |

기본은 `Timeout` 을 성공으로 간주한다 — 송신 경로는 살아 있고 그 홉만 조용했다는 뜻이다.

datagram 후보는 **TTL 1..3 을 훑는다**(`kVerifyMaxTTL` / `verifyMaxTTL` = 3, 두 구현 동일).
1발만 보고 기각하면 **첫 홉이 정당하게 침묵하는 흔한 구성**에서 멀쩡한 소켓을 강등시키기 때문이다.
같은 TTL 을 재시도하는 것으로는 부족하다 — 묻는 것이 "이 패킷이 유실됐는가"가 아니라 "이 소켓이
TTL 만료를 관측할 수 있는가"이므로, TTL 을 옮겨야 판별력이 생긴다. 수신이 구조적으로 불가능한
소켓은 셋 다 침묵하므로 판별은 유지된다.

**ICMP datagram 소켓만 이 기준이 다른 이유**: Linux 의 ping 소켓은 TTL 제한 패킷을 정상적으로
내보내지만 라우터의 Time Exceeded 를 **일반 수신 경로로 주지 않는다.** 그 메시지는 소켓 에러 큐
(`IP_RECVERR` / `MSG_ERRQUEUE`)로 가고, 이 프로그램은 에러 큐를 읽지 않는다. 그러면 이 소켓은
기본 기준을 통과한 뒤 `mode: raw` · `degraded: false` 를 표시한 채 **중간 홉의 responder 를 하나도
관측하지 못한다** — 위 표에서 Windows raw 소켓을 후보에서 뺀 것과 같은 실패 양상이다.
그래서 이 후보만은 **무언가를 관측해야** 채택한다. `Timeout` 이면 다음 후보(`SOCK_RAW`)로 넘어간다.

이 판정은 여전히 완전하지 않다 — 근처 3홉이 모두 침묵하면 멀쩡한 소켓도 기각된다. 그러나 오탐의
결과는 이미 검증된 `SOCK_RAW`/`command` 경로와 정직한 `degraded` 표시이고, 조치 전 동작의 결과는
조용히 빈 경로 표에 `degraded: false` 였다. 이 비대칭 때문에 이쪽을 택했다.

기각 사유 문구는 **"Time Exceeded 를 볼 수 없다"가 아니라 "볼 수 없을 수 있다"** 로 적는다.
한 번의 훑기로는 소켓의 무능력과 조용한 근거리 경로를 구분할 수 없으므로, 로그가 구분했다고
주장해서는 안 된다.
(이 규칙은 양쪽 구현의 회귀 테스트로 고정한다.)

`--force-command` 로 degraded 백엔드를 강제할 수 있다. 그렇지 않으면 폴백 경로는 "더 나은 백엔드가
없는 호스트"에서만 실행되어 프로그램에서 가장 검증이 덜 된 코드가 된다.

### 6.3 상관 (correlation)

와이어 상의 id/seq 를 억지로 맞추지 않는다. 내부 `ProbeId{generation,family,ttl,attempt}` 로 맞춘다.

- **raw(POSIX/Go)**: ICMP id(pid 하위 16bit) + seq 로 매칭. `TTLExpired` 는 페이로드에 인용된
  원본 IP+ICMP 헤더에서 seq 를 파싱해 매칭. `probeTimeout` 지난 늦은 응답은 **버린다**
  (avg/jitter 오염 방지).
- **helper(Windows)**: 호출 1회 = outstanding 1개. reply buffer 자체가 상관 수단이다.
  숨겨진 seq 를 복원하려 하지 않는다.
- **command**: 논리 슬롯당 동시 1개만 허용하고 그 호출의 출력으로 상관한다.

### 6.4 command 폴백의 degraded 규칙

- **로케일 고정 대신 로케일 무관 파서.** POSIX 는 `LC_ALL=C`/`LANG=C` 를 자식 환경에 넣는다.
  Windows 는 표시 언어를 이렇게 고정할 수 없으므로(그리고 `chcp` 로도 표시 언어는 바뀌지 않는다),
  **파서 자체가 로케일에 의존하지 않게** 만들었다: 홉 번호, IP 리터럴, `<n> ms` 그룹만 읽으며
  이 세 가지는 모든 표시 언어에서 ASCII 다. 한국어 Windows 의
  `요청 시간이 만료되었습니다.` 줄은 IP 도 시간도 없으므로 timeout 으로 파싱된다.
  이것은 원래 요구사항("로케일을 고정한다")보다 **강한** 보장이며, 골든 픽스처
  `testdata/tracert-windows-ko.txt` 가 이를 검증한다.
- 파서는 **골든 출력 테스트**를 갖는다 (`testdata/`, 두 구현이 **같은 파일**을 읽는다).
  파싱이 실패하면 `BackendError` + `degraded-mode` 이벤트, 크래시 금지.
  쓰레기 입력에서 **샘플을 0개** 만들어야 한다 — 유령 timeout 을 만들면 정상 경로의 손실률이 100% 가 된다.
- degraded 모드에서 **비활성**: `jitterMs`/`stdevMs`(null 고정), `TRANSIT_ONLY` 판정(→`SILENT`),
  responder 다중성(ECMP) 추적(→ primary 1개만 노출).
- 헤더에 `mode: command (degraded)` 를 표시한다.
- 자식 프로세스는 **죽일 수 있어야 한다.** `popen` 은 핸들을 주지 않아 종료 시 무한 대기가 되므로
  두 구현 모두 프로세스 핸들/PID 를 보유하고 `close()` 에서 종료시킨다. 30홉 × 3프로브 sweep 은
  정상적으로도 수 분이 걸릴 수 있어 §3.3 의 유한 드레인 요구와 충돌한다.

**알려진 한계 (§4.4 예산과의 불일치)**: command 모드의 sweep 트래픽은 전역 10 pps 예산에
**계상되지 않는다.** `tracert`/`traceroute` 가 자기 페이싱을 스스로 결정하고 우리는 홉당 프로브 수를
제어할 수 없기 때문이다(Windows `tracert` 에는 `-q` 가 없다). 목적지 ping 만 예산 안에 있다.
이를 고치려면 OS 도구 대신 TTL 별 자체 호출로 바꿔야 하고, 그건 이 폴백의 존재 이유와 모순된다.

### 6.5 알려진 한계 (문서화 의무)

- **ECMP 플로우 고정 없음.** ICMP 프로브로는 5-tuple 해시를 제어할 수 없고, Windows IP Helper 는
  더 약하다. 따라서 같은 TTL 이 서로 다른 라우터를 볼 수 있다 → 표는 "TTL=N 에서 관측된 응답자"로
  라벨하고 다중 responder 를 `+N` 으로 노출한다. Paris/Dublin traceroute 는 v1.0 범위.
- **MPLS 터널 / 숨은 홉** 은 TTL 이 소모되지 않아 표에 나타나지 않는다.
- **비대칭 필터** (Time Exceeded 는 막고 Echo Reply 는 허용, 또는 반대) 를 구분할 수 없다.
- ICMP 전 구간 차단이어도 목적지 L7 은 살아 있을 수 있다 → `health` 결과와 홉 분류는 **독립**이다.

---

## 7. 보강 정보 (enrich)

프로브 경로에서 분리된 별도 워커. 캐시 소유자는 `enrich` 모듈이다.

| 항목 | 방법 | 캐시 TTL |
|------|------|---------|
| rDNS | `getnameinfo` / `net.LookupAddr` | 10 분 |
| ASN/ORG | Team Cymru DNS: `<reversed-ip>.origin.asn.cymru.com` TXT → `AS | prefix | CC | registry | date`, 이어서 `AS<n>.asn.cymru.com` TXT 로 org 명 | 60 분 |
| A/AAAA/PTR | 표준 리졸버 | 5 분 |

- 선택 홉 변경 시 **300 ms 디바운스** 후 조회. 스냅샷마다 조회 금지.
- 사설/예약 주소(RFC1918, CGNAT, link-local, loopback)는 조회를 건너뛰고 `-` 로 채운다.
- `w` 키는 **ASN/ORG 조회**다. full WHOIS 파서는 범위 밖 — UI 라벨도 `ASN` 으로 쓴다.

---

## 8. UI 계약

### 8.1 키바인딩

| 키 | 동작 |
|----|------|
| `q` / `Ctrl+C` | 종료 (§3.3 프로토콜) |
| `p` | 일시정지 토글 — 프로브 발행만 멈추고 미완료 프로브는 회수 |
| `↑`/`↓` / `k`/`j` | 홉 선택 |
| `r` | 재프로브 — generation +1, 통계 초기화, trace 재실행 |
| `Tab` | 포커스 순환 (좁은 화면의 탭 전환) |
| `d` | 선택 홉 DNS 재조회 |
| `w` | 선택 홉 ASN/ORG 재조회 |
| `/` | 대상 변경 입력 모드 (Enter 확정, Esc 취소) |
| `s` / `n` | **예약**. 누르면 `not enabled in this build (v1.0)` 토스트만 (R1-1 #10) |

### 8.2 반응형 breakpoint

| 폭 | 레이아웃 |
|----|---------|
| `>= 120` | 계획서 §4 전체 배치 (좌 PATH×PING + 우 2패널 폭 46 + 중단바 + 로그) |
| `100..119` | 우측 패널 폭 36 으로 축소, rDNS/ASN 컬럼 생략 |
| `< 100` | 우측 패널 접기 → PATH×PING 전체폭 + `Tab` 으로 RESOLVE/LOCAL 탭 전환 (narrow 에서 `Tab` 은 이 2개만 순환) |
| `< 24` 행 | 로그 3줄로 축소, 스파크라인 유지 |

**높이 예산은 렌더 전에 확정한다.** 모든 패널 높이를 미리 계산하고, 터미널이 짧으면
**가치가 낮은 순서로 패널을 포기**한다. 최소 높이를 강제해 화면을 조립하면 터미널보다 큰 화면이 만들어져
하단이 잘린다(80×24, 40×12 에서 실제로 발생했다 — UX 리뷰 지적).

포기 순서: **로그 행 수(4→1) → 접힌 우측 탭(9→6→0) → 중단바 → 로그 전체**.
PATH×PING 표는 프로그램의 존재 이유이므로 항상 살린다(최소 3행).

고정 크롬 높이(두 구현 공유): 헤더 5, 중단바 4, 로그 = 행수+3(제목 1 + 테두리 2).
패널 제목은 **테두리가 아니라 첫 콘텐츠 행**이다 — FTXUI 의 `window()` 는 제목을 테두리에 넣어
같은 높이에서 콘텐츠 행이 1행 더 생기므로, C++ 도 Go 와 같은 구조(`vbox{title, content} | borderRounded`)를
쓴다. 이 계산은 양쪽에서 `PlanLayout`/`planLayout` 순수 함수로 분리해 단위 테스트한다.

### 8.3 표시 규칙

- 값 없음: `lossPct=null → ---`, `rtt=null → -`, `jitter=null → —`
- `SILENT` → `* (no reply)` · `TRANSIT_ONLY` → `* (pass, no ICMP)` · `UNKNOWN` → `···`
  ("transit ok" 는 운영자에게 "무엇이 OK 인가(경로? ICMP?)"로 모호하다는 UX 리뷰 지적을 반영)
- responder 가 2개 이상이면 primary 뒤에 `+N ecmp` (`+N` 만으로는 ECMP 임이 드러나지 않는다)
- **색만으로 정보를 전달하지 않는다.** `DEGRADED` 행은 빨간색 외에 호스트 칸에 `!loss` 를 붙인다.
  모노크롬 터미널과 적녹 색약 사용자에게 색은 없는 것과 같다.
- 선택 홉은 `▶` 마커, 중단바 스파크라인은 선택 홉의 `stats.spark` 를 그린다.
  홉 목록이 줄어들면(재프로브·대상 변경) 선택을 **클램프하고 엔진에 재통지**한다 — 그러지 않으면
  스파크라인이 빈 채로 남고 사용자가 되돌릴 방법이 없다.
- `▶ ` 마커는 폭 계산 없이 **바이트 그대로** 출력한다. U+25B6 은 East Asian Width 가 Ambiguous 라
  폭 테이블이 로케일에 따라 1 또는 2 를 주고, Go 와 C++ 의 폭 테이블이 이 문자에 대해 일치하지 않는다.
  동일 바이트를 내보내면 터미널이 어떻게 렌더하든 두 구현이 동일하게 보인다.
- 스크롤 오프셋은 **선택 홉의 인덱스**로 계산한다. `selected` 는 TTL 이므로 목록이 TTL 1부터
  빈틈없이 시작할 때만 인덱스와 같다.

---

## 9. Parity 검증 방법

디렉터리 미러링은 parity 를 보장하지 않는다 (R1-5). 실제 검증은 두 층으로 한다.

1. **결정론적 리플레이 비교** — 두 바이너리 모두
   `--replay <scenario.json> --emit-snapshot` 를 지원한다.
   동일 `ProbeResult` 스트림을 주입해 정규화 JSON 스냅샷을 만들고 **바이트 비교**한다.
   시간은 시나리오가 제공하는 가상 monotonic 값을 쓴다(벽시계 배제).
   실행: `scripts/parity.ps1`
2. **체크리스트** — [`parity-checklist.md`](parity-checklist.md) 로 UI/키/실패경로를 사람이 대조.

리플레이 모드는 소켓을 열지 않으므로 CI 와 비권한 환경에서도 돌아간다.
