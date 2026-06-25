# Changelog

[Keep a Changelog](https://keepachangelog.com/) 형식. 버전은 [SemVer](https://semver.org/).

## [Unreleased]

### Added

- **요청 인스펙터/에코 서버** (`serve`) — 보내는 쪽이 아니라 *받는* 쪽. 들어오는 모든 HTTP 요청을
  콘솔에 dump(method/target/헤더/바디, JSON 바디는 pretty·바이너리는 hexdump)하고 기본적으로 그
  요청을 JSON으로 에코백한다(httpbin/RequestBin 류). 클라이언트·프론트·웹훅 발신자가 *실제로 무엇을
  보내는지* 확인하는 API 디버깅용. mock 응답(`--status`/`--delay`/`--respond-body`·`--respond-file`/
  `--respond-type`/`--respond-header`/`--no-echo`), `--json` NDJSON 로그, `--max-body` 상한,
  `--keep`로 인메모리 보관 후 `GET /__requests`(배열)·`/__requests/<seq>`(단건) 조회, HTTPS
  (`--tls-cert`/`--tls-key`). hyper 서버(http1+http2 auto) + 기존 exporter accept 루프 패턴 재사용.
  주소는 `:8080`/`8080`(→0.0.0.0)·`127.0.0.1:8080`, 무인자 기본 `127.0.0.1:8080`.
- **IP 인텔리전스** (`--asn`) — 연결 IP의 ASN·조직·등록국가(Team Cymru DNS)와 reverse DNS(PTR)를
  조회하고 인프라를 CDN/cloud/origin으로 분류해 단발 출력에 한 줄로 표시한다. 자체 DNS 클라이언트
  (dns.rs에 TXT/PTR 파서 추가)를 재사용하므로 의존성·오프라인 GeoIP DB가 없다. 예: naver=origin,
  cloudflare=CDN, google=cloud/LB.

### Changed

- **`make install`이 PATH의 활성 바이너리를 덮어쓴다** — `dirname $(command -v httprove)`로 실제
  설치 위치(brew/cargo 무관)를 감지해 `httprove`/`hpr`를 새 릴리스 빌드로 교체한다(`PREFIX=`로 변경,
  권한 없으면 sudo 폴백). 기존 `cargo install --path .` 동작은 `make install-cargo`로 보존.

## [0.3.0] - 2026-06-20

### Added

- **Prometheus 메트릭 17종 확장** (`--prom`/`--listen`) — 기존 숫자 외에 진단 신호를 메트릭으로
  노출한다. 인증서 체인 깊이/완결성/최약링크 만료(`httprove_cert_chain_depth`·`_incomplete`·
  `httprove_cert_weakest_expiry_days`, leaf만 보던 `cert_expiry_days`의 갭 보완), 협상 TLS
  정보(`httprove_tls_info`), 서버 Server-Timing 분해(`httprove_server_timing_milliseconds`),
  goodput 분포(`httprove_throughput_bytes_per_second`), 연결 재사용률·HTTP 버전 분포
  (`httprove_connection_reuse_ratio`·`httprove_hops_total`·`httprove_connection_reused_total`·
  `httprove_http_version_total`), DNS 응답 변경·IP 수(`httprove_dns_answer_changed_total`·
  `httprove_dns_resolved_ip_count`), 최신 건강 판정(`httprove_verdict_state`), 플릿 rollup
  (`httprove_fleet_phase_milliseconds`·`httprove_target_up`·`httprove_targets_total`·
  `httprove_targets_down`). 설계 문서: `docs/v0.3-metrics-spec.md`.
- **SLO·Apdex 메트릭** — `--slo 0.999`로 `httprove_slo_target_ratio`(burn-rate 알림 룰의 SLO
  목표 상수를 메트릭화; burn 계산은 PromQL에 위임), `--apdex-threshold T`로
  `httprove_apdex_satisfied_total`·`httprove_apdex_tolerating_total` 누적 카운터(latency 체감
  Apdex를 PromQL로 복원). 트랙2 검토 문서: `docs/track2-review.md`.
- **메트릭 소비 번들** — `examples/`에 Prometheus recording 룰(9개)·alert 룰(11개) +
  Grafana 대시보드(8행 25패널). httprove 메트릭으로 availability·Apdex·SLO burn-rate·
  error-budget·TTFB p95 z-score를 PromQL로 구성한다.
- **TLS 연결 보안 등급** (`--tls-grade`) — 협상된 protocol/cipher(forward-secrecy·AEAD)/
  key-exchange + HSTS + 인증서 체인(`chain::analyze` 재사용)을 종합해 A~F 등급 + 감점 사유.
  단발 출력에 한 줄 표시. 서버 cipher 전수 스캔(testssl)이 아니라 *실제 협상된 이 연결*의 구성 등급.
- **CDN/캐시 효율 진단** (`--cache-audit`) — 응답 헤더(Cache-Control/Age/X-Cache/
  CF-Cache-Status/X-Served-By/Via)로 HIT/MISS·CDN·edge·age를 요약하고, 캐시 무력화 안티패턴
  (Set-Cookie·no-store·Vary:*·max-age=0)을 짚는다. 단발 출력에 한 줄.
- **watch/alert 모드** (`--on-breach <url>`) — ping 모드에서 프로브가 breach(verdict != PASS)
  하면 webhook으로 JSON 알림을 POST한다. `--breach-after N`(연속 N회 후 발화),
  `--cooldown SECS`(재발화 억제), `--on-recover`(복구 알림). fire-and-forget이라 프로브 루프를
  막지 않으며, exec hook은 보안상 제외하고 webhook만 지원한다.
- **blackbox_exporter 호환** (`--blackbox-config <file>`) — blackbox `modules:` YAML(http
  prober)을 httprove 프로브로 변환한다. `--listen`과 함께 쓰면 `/probe?target=&module=`
  엔드포인트로 blackbox 메트릭(probe_success·probe_duration_seconds·probe_http_*·
  probe_ssl_earliest_cert_expiry)을 응답 — 기존 blackbox 잡 설정·alert·dashboard를 그대로 쓰되
  각 프로브에 httprove 단계별 진단이 붙는 drop-in 업그레이드. (의존성 추가: serde_yaml_ng)

### Fixed

- `--prom`/`--listen`의 `httprove_phase_milliseconds`에서 `stddev` stat 누락 수정 — text/TUI엔
  나오지만 Prometheus 출력에서만 빠져 있던 불일치.

## [0.2.0] - 2026-06-14

숫자를 보여주는 데서 그치지 않고 "어디가·왜 문제인지"를 판정하는 심층 진단 기능 16종.

### Added

- **건강 판정** — `--verdict`: 프로브/요약 끝에 `PASS`/`DEGRADED`/`DOWN` + 근거 한 줄.
  `--explain`: 단계를 평문 인과 문장으로 설명.
- **변경 탐지** — `diff <a.json> <b.json>` 서브커맨드(두 프로브 JSON의 변경 필드만),
  `--since-good <path>`(마지막 정상 대비 지문 변경 감지), `--on-change`(지문 변경 시 비-0 종료),
  `--annotate-deploy`.
- **백엔드·경로 국소화** — `--fanout`(DNS의 모든 A/AAAA를 개별 프로브, 불량 노드 적발),
  `--all-families`(IPv4 vs IPv6 단계별 비교), `--via <ips>` + `--ecs`(자체 DNS-over-UDP
  클라이언트로 리졸버별 POP 비교), `trace <url>` 서브커맨드(시스템 traceroute + TLS 종단 hop 주석).
- **TLS 심화** — `--check-chain`(중간 인증서 누락 + AIA 복구 가능 여부), 핸드셰이크 실패
  디코더(`hint:` 원인+해법), 인증서 블록의 체인 전체 최약링크 만료(`weakest:`).
- **캡처·연동** — `--trap`(첫 실패에서 동결 + 세션 덤프), `--record`/`replay`(인시던트 기록·재생),
  `--report <html>`(자체완결 HTML 리포트), `--otlp <endpoint>` + `--traceparent`(OTLP/HTTP span
  내보내기 + Server-Timing 파싱).

### Changed

- rustls crypto provider를 `aws-lc-rs` → `ring`으로 전환 (aarch64-linux 크로스 컴파일 단순화,
  바이너리 경량화).
- `ProbeResult`·`CertInfo`·`ProbeError` 등 핵심 타입에 `Deserialize` 추가 (저장된 프로브
  JSON 로드 — diff/replay/since-good). `CertInfo`에 `spki_sha256`(키 핀), `ProbeError`에 `hint`.

### Fixed

- DOWN 판정 헤드라인 중복(`DOWN — DOWN: …`) 제거.
- IPv6 연결 에러 포맷(`2001:…:::443`)을 `[…]:443`으로 교정.

## [0.1.1] - 2026-06-13

### Added

- `--keepalive`(연결 재사용 — 연결 비용 vs 순수 서버 시간 분리), `--expect-*` 어설션(상태/바디/
  TTFB/총시간/cert 일수, 종료 코드 3), `--warn` 임계값 강조, 멀티 타깃, Prometheus(`--prom`/
  `--listen`), 베이스라인 `--save`/`--compare`, 인증서 일괄 점검(`--cert-check`),
  멀티 타깃 TUI, TUI 하단 프로브 히스토리.
- TLS 키 교환 그룹·로컬 소켓·DNS 전체 레코드·응답 크기/전송률·주요 헤더 표시.
- `httprove update` 자가 업데이트, Homebrew cask 자동 발행(릴리스 워크플로).

### Fixed

- 첫 프로브 TLS 초기화(~100ms)가 total에 섞이던 문제, HTTP/2 total 과대 보고, 인증서 D-day
  절삭(만료 24시간 내 "0 days") 버그.

## [0.1.0] - 2026-06-13

### Added

- 초기 릴리스: 단계별 워터폴(DNS/TCP/TLS/TTFB/Download), TLS·인증서 검사, ping 모드 + 통계,
  JSON 출력, ratatui TUI, 리다이렉트 추적, `--resolve`, IPv4/IPv6, `--http1`, `-k`.
- 정식 명령 `httprove` + 단축 명령 `hpr`.

[0.2.0]: https://github.com/x-mesh/httprove/releases/tag/v0.2.0
[0.1.1]: https://github.com/x-mesh/httprove/releases/tag/v0.1.1
[0.1.0]: https://github.com/x-mesh/httprove/releases/tag/v0.1.0
