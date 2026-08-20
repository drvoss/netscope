# NetScope

**English: [README.md](README.md)**

NetScope는 ping과 traceroute 관측값에 DNS, 인터페이스, 라우팅, TCP 상태,
ASN 정보를 결합해 한 화면에 보여주는 터미널 네트워크 진단 대시보드입니다.
Go와 C++로 각각 구현되어 있으며, 리플레이 출력이 바이트 단위로 같은지
검증합니다.

> NetScope는 1.0 이전의 진단 도구이며 능동 네트워크 프로브를 보냅니다.
> 본인이 소유했거나 테스트 권한을 받은 시스템과 네트워크에만 사용하십시오.

| 구현 | 폴더 | 명령 | 기술 |
|---|---|---|---|
| Go 레퍼런스 | [`netscope-go/`](netscope-go/) | `netscope` | Go, Bubble Tea, `x/net/icmp` |
| C++ | [`netscope-cpp/`](netscope-cpp/) | `nscope` | C++20, FTXUI, standalone Asio |

## 주요 기능

- 목적지 지연시간, 손실, 지터, TCP 상태
- TTL 제한 경로 관측과 responder별 ECMP 통계
- 로컬 인터페이스, 게이트웨이, DNS, 공인 IP, ASN 정보
- 네이티브 프로브를 쓸 수 없을 때 명시적인 degraded 표시
- 대화형 TUI, 시간 제한 headless JSON, 결정론적 리플레이

무응답을 곧바로 필터링이라고 단정하지 않으며, 손실이 하위 구간에서도
이어지지 않으면 중간 라우터에 손실을 귀속하지 않습니다. 자세한 규칙은
[동작 계약](docs/netscope-spec.md)에 있습니다.

## 빌드

### Go

네트워크 및 TLS 경로에 필요한 표준 라이브러리 보안 수정이 포함된 Go 1.26.6
이상이 필요합니다.

Go 구현을 직접 설치하려면 다음을 실행하십시오.

```sh
go install github.com/drvoss/netscope/netscope-go@latest
```

또는 로컬 clone에서 빌드하십시오.

```sh
cd netscope-go
go test ./...
go build -o netscope .
```

Windows에서는 `go build -o netscope.exe .`를 사용하십시오.

### C++

CMake 3.21 이상, Ninja, C++20 컴파일러와
[vcpkg](https://github.com/microsoft/vcpkg)가 필요합니다. `VCPKG_ROOT`를
vcpkg 체크아웃 경로로 설정하십시오.

```sh
cd netscope-cpp
cmake --preset linux-release
cmake --build --preset linux-release
ctest --preset linux-release
```

Windows에서 `windows-release` 프리셋을 직접 사용하려면 MSVC developer shell이
필요합니다. 다음 PowerShell 보조 스크립트는 `vswhere`로 Visual Studio를 찾고,
MSVC 환경을 준비한 뒤 빌드와 테스트를 실행합니다. Visual Studio 18.x 호환
triplet은 해당 호스트별 우회가 필요할 때만 적용되며 Visual Studio 2022와
GitHub-hosted runner는 표준 `x64-windows` triplet을 사용합니다.

```powershell
./scripts/build-cpp.ps1 -Test
```

## 빠른 시작

```text
netscope [flags] <hostname|ip>     # Go
nscope   [flags] <hostname|ip>     # C++
```

```sh
netscope example.com
netscope --headless 10s --no-public-ip example.com
```

| 플래그 | 설명 |
|---|---|
| `--port <n>` | TCP 상태 확인 포트, 기본값 `443` |
| `--no-public-ip` | 외부 공인 IP 조회 생략 |
| `--force-command` | degraded OS 명령 백엔드 강제 |
| `--headless <duration>` | TUI 없이 측정 후 정규화 JSON 출력 |
| `--replay <file> --emit-snapshot` | 픽스처 리플레이 후 정규화 JSON 출력 |
| `--version` | 버전 출력 후 종료 |

TUI 키: `q` 종료, `p` 일시정지, 방향키 또는 `j`/`k` 홉 선택, `r`
재프로브, `Tab` 포커스 변경, `d` DNS 갱신, `w` ASN 갱신, `/` 대상 변경.

## 권한과 폴백

- Windows는 IP Helper API를 사용하므로 관리자 권한이 필요 없습니다.
- Linux는 검증된 ICMP datagram 소켓, `SOCK_RAW`, OS의
  `ping`/`traceroute` 순서로 시도합니다. raw 소켓에는 root 또는
  `cap_net_raw`가 필요할 수 있으며 command 폴백은 degraded로 표시됩니다.
- Windows IPv6는 현재 degraded command 백엔드를 사용합니다.

타임아웃만으로 ACL, ICMP rate limit, 라우터 부하, 패킷 손실을 서로
구분할 수는 없습니다.

## Go/C++ 동등성

두 구현에 같은 프로브 스트림과 가상 monotonic clock을 주입하고 정규화된
JSON 스냅샷을 바이트 단위로 비교합니다. 소켓을 열지 않아 CI에서도
결정론적으로 실행할 수 있습니다.

```powershell
./scripts/parity.ps1
./scripts/parity.ps1 -ShowDiff
```

```sh
./scripts/parity.sh
```

리플레이 동등성은 두 구현이 서로 같다는 뜻이지, 커널 백엔드의 정확성을
보장한다는 뜻은 아닙니다. 네이티브 백엔드 테스트와 플랫폼 실측도 필요합니다.

## 프로젝트 상태와 한계

현재 버전은 **v0.3.0, pre-1.0**입니다.

- Linux에서는 `SOCK_RAW` 및 command 폴백 경로를 실측했습니다. 비특권 ICMP
  datagram 경로는 더 다양한 커널 검증이 필요합니다.
- 스케줄러 cadence와 대화형 키 입력은 end-to-end 자동화되지 않았습니다.
- OS command sweep은 네이티브 백엔드와 같은 패킷 속도 예산을 강제할 수 없습니다.
- 공인 IP와 ASN enrichment는 외부 서비스에 의존할 수 있으며, 실패 시 측정은
  계속하되 값을 사용할 수 없다고 명시합니다.
- Go와 C++을 함께 설치할 수 있도록 실행 파일 이름이 다릅니다.

자세한 검증 범위는 [동등성 체크리스트](docs/parity-checklist.md)를 참고하십시오.

## 개발

```text
netscope-go/     Go 레퍼런스 구현
netscope-cpp/    C++ 구현
testdata/        공용 파서 픽스처와 리플레이 시나리오
scripts/         빌드 및 동등성 검사 스크립트
docs/            공개 동작 계약과 검증 문서
```

PR 전 확인사항은 [CONTRIBUTING.md](CONTRIBUTING.md), 제3자 라이선스는
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), 보안 문제 보고 방법은
[SECURITY.md](SECURITY.md)를 참고하십시오.

## 라이선스

MIT — [LICENSE](LICENSE) 참고.
