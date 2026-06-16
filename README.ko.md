# httprove

> probe + prove your HTTP services.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/x-mesh/httprove?sort=semver)](https://github.com/x-mesh/httprove/releases)
[![Homebrew](https://img.shields.io/badge/homebrew-x--mesh%2Ftap-orange)](https://github.com/x-mesh/homebrew-tap)

**한국어** · [English](README.md)

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

## 주요 기능

- **단계별 워터폴** — DNS/TCP/TLS/TTFB/Download를 쪼개 병목 위치 식별
- **TLS 심층 검사** — 버전/cipher/키교환, 체인 만료(최약링크)·SAN·발급자, 핸드셰이크 실패 원인 디코딩, 체인 완결성+AIA 복구
- **건강 판정** — `--verdict`로 PASS/DEGRADED/DOWN + 근거 한 줄, `--explain` 평문 설명
- **백엔드·경로 국소화** — `--fanout`(IP별), `--all-families`(v4/v6), `--via`(멀티 리졸버), `trace`(traceroute)
- **변경 추적** — `diff`(두 캡처 비교), `--since-good`(마지막 정상 대비 지문 변경)
- **지속 모니터링** — ping 모드 + 백분위 통계, 실시간 TUI 대시보드, 멀티 타깃
- **합성 모니터링** — `--expect-*` 어설션(종료 코드 3), `--warn` 임계값 강조
- **연동** — JSON/NDJSON, Prometheus(`--prom`/`--listen`), OTLP(`--otlp`), HTML 리포트(`--report`)
- **캡처** — `--trap`(첫 실패 동결), `--record`/`replay`(인시던트 기록·재생)
- **운영** — keep-alive 모드, `--resolve`, 인증서 일괄 점검(`--cert-check`), 베이스라인 비교
- **두 명령** — `httprove`(정식)/`hpr`(단축), `httprove update`로 자가 업데이트

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

## 심층 진단 (숫자를 결론으로)

숫자를 보여주는 데서 그치지 않고 "어디가·왜 문제인지"를 판정한다.

### 건강 판정 + 평문 설명

```bash
httprove --verdict https://api.example.com   # 끝에 PASS/DEGRADED/DOWN + 근거 한 줄
httprove --explain https://api.example.com   # "TCP 39ms, 서버 21ms(TTFB), 총 60ms over HTTP/2"
```

종료 코드는 PASS=0 / DOWN=1로 합성 모니터링에 바로 쓴다.

### 백엔드·경로 국소화

```bash
httprove --fanout https://api.example.com          # DNS의 모든 IP를 개별 프로브, 불량 백엔드(outlier) 적발
httprove --all-families https://api.example.com    # IPv4 vs IPv6 단계별 비교
httprove --via 1.1.1.1,8.8.8.8 https://api.example.com   # 리졸버별 응답 IP/POP 비교 (--ecs로 client-subnet)
httprove trace https://api.example.com             # 시스템 traceroute + TLS 종단 hop 주석
```

### TLS 신뢰 심화

```bash
httprove --check-chain https://api.example.com   # 중간 인증서 누락 + AIA 복구 가능 여부
httprove https://expired.example.com             # 핸드셰이크 실패를 원인+해법으로 번역 (hint:)
```

`--check-chain`은 "브라우저는 되는데 curl/Go는 실패"하는 미완 체인을 잡아낸다.
인증서 블록은 항상 체인 전체의 최약 링크 만료일(`weakest:`)을 표시한다.

### 변경 추적 · 캡처 · 연동

```bash
httprove https://x --json > before.json          # 두 시점/엔드포인트 비교
httprove diff before.json after.json             # 바뀐 필드만 (cert serial, IP set, TLS, 헤더…)
httprove --since-good /var/lib/httprove/x.state https://x   # 마지막 정상 대비 지문 변경 시 비-0
httprove --since-good x.state --on-change https://x         # CI: 지문이 바뀌면 비-0 종료 (배포 검증)
httprove --annotate-deploy before.json https://x            # 저장된 프로브 대비 변경 주석
httprove --trap -c 0 https://x                   # 첫 실패에서 동결, 전체 트랜잭션 덤프
httprove --record sess.json -c 100 https://x && httprove replay sess.json   # 인시던트 기록/재생
httprove --report out.html https://x             # 공유용 단일 HTML 리포트
httprove --otlp http://collector:4318 --traceparent https://x   # OTLP span 내보내기 + traceparent 주입
```

`--on-change`는 지문(cert·IP·TLS·헤더)이 직전 정상 상태와 달라지면 종료 코드를 비-0으로
바꿔, 배포 후 "의도치 않은 변경"을 CI에서 잡는 데 쓴다.

## 활용 시나리오

- **"서비스가 느린데 어디가 느린지 모르겠다"** → 단발 워터폴 + `--verdict`로 DNS/네트워크/서버 중 병목 판정
- **"전부 느린가, 한 노드만 느린가"** → `--fanout`으로 백엔드 IP별 비교, 불량 노드 적발
- **"무엇이 바뀌었나"** → `--since-good` 또는 `diff`로 cert/IP/TLS/헤더 변경 추적
- **배포 전후 레이턴시 비교** → `--save`/`--compare`로 p50/p95 delta%
- **간헐적 타임아웃 추적** → `--trap`으로 첫 실패 동결, 또는 `--tui`로 관찰
- **인증서 만료/체인 점검** → `--cert-warn`·`--check-chain`·`--cert-check`로 cron 알람
- **합성 모니터링** → `--expect-*`(exit 3) + `--otlp`로 트레이싱 백엔드 연동

## 종료 코드

| 코드 | 의미 |
|:---:|------|
| 0 | 모든 프로브 통과 (verdict PASS/DEGRADED) |
| 1 | 네트워크 실패·실행 오류 (verdict DOWN), `--fanout`/`--cert-check` 등에서 결함 발견 |
| 3 | 네트워크는 성공했으나 `--expect-*` 어설션 위반 |

## 구조

```
src/
├── lib.rs         # 진입점 cli_main: 서브커맨드/모드 라우팅, 시그널, 종료 코드
├── main.rs        # `httprove` 진입점 (lib::cli_main 호출)
├── bin/hpr.rs     # `hpr` 진입점 (동일 바이너리)
├── cli.rs         # clap 인자 → ProbeConfig / Expectations / WarnThresholds
├── types.rs       # 공유 타입 (ProbeResult/CertInfo/Verdict/Fingerprint/ChainAnalysis, Serialize+Deserialize)
├── probe.rs       # 핵심: 수동 DNS/TCP/TLS/HTTP 연결 + 단계별 실측, keepalive (rustls ring + hyper)
├── cert.rs        # x509 체인 분석 (SPKI 핀 포함)
├── cert_check.rs  # --cert-check 일괄 점검
├── hash.rs        # 공유 SHA-256 (의존성 없이; cert 핀·자가 업데이트 검증)
├── verdict.rs     # 건강 판정 PASS/DEGRADED/DOWN (--verdict/--explain)
├── diff.rs        # 지문 추출 + 프로브 JSON diff (diff 서브커맨드/--since-good)
├── fanout.rs      # --fanout(IP별), --all-families(v4/v6)
├── dns.rs         # 자체 DNS-over-UDP 클라이언트 (--via 멀티 리졸버 + --ecs)
├── trace.rs       # 시스템 traceroute + TLS 종단 hop 주석
├── chain.rs       # 체인 완결성/AIA 복구, 최약링크 만료, 핸드셰이크 에러 디코더
├── record.rs      # --record/replay, --trap (첫 실패 동결)
├── otlp.rs        # OTLP/HTTP span export, Server-Timing 파싱, traceparent
├── exporter.rs    # --listen Prometheus exporter
├── stats.rs       # Welford + 링버퍼 백분위
├── runner.rs      # 프로브 반복 루프 (멀티 타깃/간격/일시정지/취소)
├── update/        # httprove update — 설치방식 감지 + 자가 교체
├── output/        # 텍스트(워터폴/ping/요약) + JSON + prom + baseline + HTML 리포트
└── tui/           # ratatui 대시보드 (멀티 타깃)
```

## 라이선스

[MIT](LICENSE)
