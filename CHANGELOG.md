# Changelog

[Keep a Changelog](https://keepachangelog.com/) 형식. 버전은 [SemVer](https://semver.org/).

## [Unreleased]

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
