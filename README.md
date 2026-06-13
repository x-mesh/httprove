# httprove

> probe + prove your HTTP services.

SRE를 위한 HTTP(S) 서비스 점검 도구. 요청의 모든 단계를 워터폴로 쪼개서 측정하고,
TLS 인증서를 검사하며, ping처럼 지속적으로 프로브할 수 있다. CLI와 TUI를 모두 지원한다.

명령어는 두 가지 — 정식 명령 **`httprove`** 와 단축 명령 **`hpr`** (완전히 동일하다.
이 문서의 모든 예시는 `hpr`로 바꿔 써도 된다).

```
DNS      ▕██▏              12.3 ms
TCP        ▕███▏           18.1 ms
TLS           ▕█████▏      33.9 ms
TTFB               ▕████▏  51.2 ms
Download               ▕▏   2.1 ms
Total                     117.6 ms
```

## 무엇을 측정하나

매 프로브마다 **새 연결을 직접 수립**하여 각 단계를 실측한다 (커넥션 풀 재사용 없음 —
매번 전체 스택을 측정하는 것이 목적):

| 단계 | 의미 | 병목 시 의심 지점 |
|------|------|------|
| DNS | 이름 해석 (`getaddrinfo`) | 리졸버, TTL, 네거티브 캐시 |
| TCP | TCP 3-way handshake | 네트워크 RTT, SYN drop, 방화벽 |
| TLS | TLS 핸드셰이크 (rustls) | 인증서 체인 크기, OCSP, TLS 버전 |
| TTFB | 요청 전송 → 응답 헤더 수신 | **서버 처리 시간**, 업스트림, DB |
| Download | 응답 바디 전체 수신 | 대역폭, 응답 크기, 압축 |

추가로 수집: 협상된 HTTP 버전(ALPN h2/http1.1), TLS 버전/cipher/키 교환 그룹(X25519 등),
인증서 체인(만료일, D-day, SAN, 발급자, 키/서명 알고리즘, 체인 구조),
DNS 전체 레코드, 로컬 소켓 주소(소스 IP), 응답 크기/전송률,
주요 응답 헤더(server, content-type, 캐시/CDN 상태).

## 설치

### Homebrew (권장)

```bash
brew install x-mesh/tap/httprove
```

### 설치 스크립트

```bash
curl -fsSL https://raw.githubusercontent.com/x-mesh/httprove/main/install.sh | sh
```

OS/아키텍처를 감지해 최신 릴리스 바이너리를 받고 sha256으로 검증한 뒤
`~/.local/bin`(또는 `/usr/local/bin`)에 설치하고 `hpr` 별칭을 만든다.

### 업데이트

설치 방식에 맞춰 스스로 최신 버전으로 갱신한다:

```bash
httprove update              # brew면 brew upgrade로 위임, 그 외엔 바이너리 자가 교체
httprove update --check      # 새 버전 여부만 확인 (최신=exit 0, 갱신가능=exit 1)
httprove update --dry-run    # 무엇을 할지만 출력
httprove update --to v0.2.0  # 특정 버전 고정 (manual 설치)
```

### 소스 빌드

```bash
make release          # 릴리스 빌드 → ./target/release/{httprove,hpr}
make build            # 디버깅 빌드 → ./target/debug/{httprove,hpr}
make ci               # 포맷 검사 + clippy + 테스트 + 릴리스 빌드
make smoke            # 실서비스 대상 스모크 테스트
make install          # ~/.cargo/bin에 httprove + hpr 설치
make help             # 전체 타깃 목록
```

cargo를 직접 써도 된다: `cargo build --release`

## 사용법

### 단발 점검 (워터폴 + 인증서 상세)

```bash
httprove https://api.example.com
httprove https://api.example.com -v        # 응답 헤더 + 인증서 체인 전체
httprove https://api.example.com --json    # 스크립트 연동용 JSON
```

### ping 모드 (지속 모니터링)

```bash
httprove -c 0 https://api.example.com            # Ctrl-C까지 1초 간격
httprove -c 100 -i 0.5 https://api.example.com   # 0.5초 간격 100회
```

```
seq=0 93.184.216.34 200 dns=12.3ms tcp=18.1ms tls=33.9ms ttfb=51.2ms dl=2.1ms total=117.6ms
seq=1 93.184.216.34 200 dns=1.1ms tcp=17.9ms tls=32.2ms ttfb=49.8ms dl=2.0ms total=103.0ms
^C
--- https://api.example.com httprove statistics ---
2 probes: 2 ok, 0 failed (0.0% loss)
phase        min       avg       p50       p95       max    stddev
...
```

종료 코드: 모든 프로브 통과 `0` │ 네트워크 실패/실행 오류 `1` │
네트워크는 성공했지만 `--expect-*` 어설션 위반 `3` (cron/알람 연동용).

### 어설션 (합성 모니터링)

```bash
httprove --expect-status 200 --expect-ttfb 500 --expect-body '"ok"' https://api.example.com/health
httprove --expect-status 2xx,3xx https://example.com     # 클래스 표기 지원
httprove --expect-cert-days 30 https://api.example.com   # 인증서 잔여 30일 미만이면 exit 3
```

위반 시 ping 라인/단발 출력에 `EXPECT-FAIL: …`이 표시되고 종료 코드 3으로 끝난다.

### 임계값 강조

```bash
httprove -c 0 --warn ttfb=300 --warn total=800 https://api.example.com
```

임계 초과 단계는 노랑(≥1x), 빨강(≥2x)으로 강조된다 (CLI/TUI 공통).

### keep-alive 모드 (연결 비용 vs 서버 시간 분리)

```bash
httprove --keepalive -c 0 https://api.example.com
```

첫 프로브만 DNS/TCP/TLS를 수행하고 이후엔 같은 연결로 요청만 보낸다
(`conn=reused` 표시). 신규 연결 프로브와 비교하면 "커넥션 수립이 느린지,
서버 처리가 느린지"를 분리할 수 있다.

### 멀티 타깃

```bash
httprove -c 0 https://a.example.com https://b.example.com   # [host] 태그로 인터리브
httprove --tui https://a.example.com https://b.example.com  # 차트 겹쳐 그리기, tab으로 전환
```

### Prometheus 연동

```bash
# node_exporter textfile collector용 스냅샷
httprove -c 10 --prom https://api.example.com > /var/lib/node_exporter/httprove.prom

# 상시 exporter (무한 프로브 + /metrics 서버)
httprove --listen 0.0.0.0:9912 -i 5 https://api.example.com https://b.example.com
curl localhost:9912/metrics
```

`httprove_phase_milliseconds{target,phase,stat}`, `httprove_probes_total`,
`httprove_cert_expiry_days` 등 단계별 백분위가 그대로 노출된다.

### 베이스라인 비교 (배포 전후 회귀 감지)

```bash
httprove -c 30 --save before.json https://api.example.com    # 배포 전
httprove -c 30 --compare before.json https://api.example.com # 배포 후: p50/p95 delta% 테이블
```

### 인증서 일괄 점검

```bash
httprove --cert-check api.example.com b.example.com:8443 @domains.txt
httprove --cert-check --json @domains.txt | jq '.[] | select(.days_remaining < 30)'
```

만료 임박 순 테이블 출력. EXPIRED/연결 실패가 있으면 exit 1.

### TUI 대시보드

```bash
httprove --tui https://api.example.com
```

실시간 레이턴시 차트 + 최신 워터폴 + 단계별 통계 + 프로브 히스토리(하단,
ping 라인 스타일로 최근 결과를 한 줄씩 — 실패는 빨강으로 표시).
키: `q` 종료, `space` 일시정지, `r` 통계 초기화.

### 문제 조사용 옵션

```bash
httprove -L https://example.com              # 리다이렉트 추적 (hop별 측정)
httprove --resolve 10.0.0.5 https://api.example.com   # 특정 백엔드 직접 타격 (DNS 우회, SNI/Host 유지)
httprove -4 https://api.example.com          # IPv4 강제 (-6: IPv6)
httprove --http1 https://api.example.com     # HTTP/1.1 강제 (h2 협상 비활성)
httprove -k https://expired.internal         # 인증서 검증 생략 (체인 정보는 그대로 수집)
httprove -t 3 https://api.example.com        # 프로브 전체 타임아웃 3초
httprove -X POST -d '{"ping":1}' -H 'Content-Type: application/json' https://api.example.com/health
httprove --cert-warn 14 https://api.example.com   # 만료 14일 전부터 경고
```

실패 시 **어느 단계에서** 실패했는지 보고한다 (`ERROR(dns)`, `ERROR(tls): certificate has expired`, …).

### JSON 출력 (모니터링 파이프라인 연동)

```bash
httprove -c 10 --json https://api.example.com | jq 'select(.type=="probe") | .total_ms'
```

- 프로브 1건당 한 줄: `{"type":"probe","seq":0,"hops":[{"timings":{...},"cert_chain":[...],...}],...}`
- 마지막에 요약 한 줄: `{"type":"summary","phases":{"ttfb":{"p95":...},...},"status_counts":{"200":10},...}`

## 활용 시나리오

- **"서비스가 느린데 어디가 느린지 모르겠다"** → 단발 워터폴로 DNS/네트워크/서버 중 병목 식별
- **배포 전후 레이턴시 비교** → `-c 30 --json` 두 번 돌려 p95 비교
- **간헐적 타임아웃 추적** → `--tui` 또는 `-c 0`로 켜두고 실패 시점/단계 관찰
- **인증서 만료 점검** → `--cert-warn`과 종료 코드로 cron 알람
- **LB 뒤 특정 백엔드 점검** → `--resolve <ip>`로 노드별 직접 측정

## 구조

```
src/
├── lib.rs         # 모드 결정(단발/ping/TUI/exporter/cert-check), 시그널, 종료 코드
├── main.rs        # `httprove` 진입점 (lib::cli_main 호출)
├── bin/hpr.rs     # `hpr` 진입점 (동일)
├── cli.rs         # clap 인자 → ProbeConfig / Expectations / WarnThresholds
├── types.rs       # 공유 타입 (ProbeResult, PhaseTimings, CertInfo, …)
├── probe.rs       # 핵심: 수동 DNS/TCP/TLS/HTTP 연결 + 단계별 실측, keepalive (rustls + hyper)
├── cert.rs        # x509 체인 분석
├── cert_check.rs  # --cert-check 일괄 점검
├── exporter.rs    # --listen Prometheus exporter
├── stats.rs       # Welford + 링버퍼 백분위
├── runner.rs      # 프로브 반복 루프 (멀티 타깃/간격/일시정지/취소)
├── output/        # 텍스트(워터폴/ping/요약) + JSON + prom + baseline
└── tui/           # ratatui 대시보드 (멀티 타깃)
```
