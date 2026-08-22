# httprove 메트릭 소비 번들

httprove가 `--prom`/`--listen`으로 노출하는 메트릭을 Prometheus + Grafana에서 바로 쓰기 위한
recording 룰·alert 룰·대시보드입니다. httprove는 **무상태 스냅샷 익스포터**라 시간축
(rate·burn-rate·availability·z-score)은 Prometheus가 계산합니다 — 그 계산을 이 번들이 담습니다.

## 파일

| 파일 | 내용 |
|---|---|
| `prometheus-recording-rules.yml` | freshness age · availability · Apdex · SLO burn-rate · error-budget · TTFB z-score |
| `prometheus-alerts.yml` | exporter/probe freshness · target health · TLS · SLO · latency · DNS 알림 |
| `grafana-dashboard.json` | Exporter Freshness / Fleet / Latency / TLS·Cert / Verdict / Connection / DNS / SLO |

## 사용

1. httprove를 exporter로 띄웁니다:

   ```bash
   httprove --listen 0.0.0.0:9912 -i 5 --slo 0.999 --apdex-threshold 200 https://api.example.com
   ```

   `--slo`/`--apdex-threshold`는 SLO burn-rate·Apdex 룰이 쓰는 메트릭(`httprove_slo_target_ratio`,
   `httprove_apdex_*_total`)을 노출합니다. 생략하면 해당 룰만 비활성화되고 나머지는 그대로 동작합니다.

2. Prometheus가 스크레이프하고 룰을 로드합니다:

   ```yaml
   scrape_configs:
     - job_name: httprove
       static_configs: [{ targets: ['localhost:9912'] }]
   rule_files:
     - prometheus-recording-rules.yml
     - prometheus-alerts.yml
   ```

3. Grafana에서 `grafana-dashboard.json`을 Import하고 Prometheus datasource를 선택합니다.

## 운영 runbook

1. **Exporter missing**: `HttproveExporterMissing`이면 target 장애를 보기 전에 exporter process,
   Prometheus scrape target과 네트워크 경로를 확인한다.
2. **Probe loop stalled**: `httprove_exporter_up`은 있지만 `HttproveProbeLoopStalled`이면
   `Last Probe Attempt Age`가 `2 × interval + timeout`을 넘었는지 확인한다.
3. **Never succeeded**: attempt timestamp가 `0`보다 크고 success timestamp가 `0`이면 첫 성공이
   아직 없다. 최근 probe error와 TLS/DNS 설정을 확인한다.
4. **Stale success**: attempt는 갱신되지만 success age만 커지면 probe loop는 돌고 있으나 계속
   실패하는 상태다. `TargetDown`과 단계별 latency/error를 함께 본다.

`httprove_exporter_config_generation`은 `1`, `httprove_exporter_config_reload_supported`는 `0`이다.
runtime reload는 지원하지 않으므로 설정 변경 후 exporter를 재시작한다. timestamp `0`은 no-data
sentinel이고 실제 Unix epoch로 해석하지 않는다.

## Redirect 진단

```bash
httprove -L --redirect-diagnostics https://example.com
```

완료된 hop이 둘 이상이면 hop별 status, 전체 redirect 시간 기여도, dominant phase, origin 전환과
connection reuse를 text로 표시한다. 추가 요청을 보내지 않고 관측된 값만 설명한다. 중간 hop에서
실패하면 완료된 hop까지만 진단하며 원인을 단정하지 않는다. 기본값은 비활성이고 `--json`, TUI,
exporter, cert-check와 함께 사용할 수 없으므로 기존 NDJSON·Prometheus 계약과 exit code는 변하지 않는다.

## 호환성과 rollback

| 표면 | 변경 | 비활성화·rollback |
|---|---|---|
| CLI/NDJSON/exit code | 기존 계약 유지, opt-in flag만 추가 | `--redirect-diagnostics`를 생략 |
| Prometheus exporter | exporter-only family 추가 | 새 alert를 먼저 비활성화 |
| rules/dashboard | freshness rule·alert·panel 추가 | 새 panel과 recording rule 제거 |
| binary | persistent state·migration 없음 | 필요하면 이전 binary로 복귀 |

기본 gate는 `make fmt-check`, `make lint`, `make test`, `make release`다. `make smoke`는 외부
네트워크를 사용하고 `promtool check rules`는 설치가 필요한 도구이므로 둘 다 선택 검증으로 남긴다.

## 설계 메모

이 번들은 트랙2 검토(`../docs/track2-review.md`)의 결론을 구현합니다: burn-rate·availability·
error-budget·z-score는 **도구에 박는 대신 룰로** 만듭니다. httprove는 무상태 카운터·게이지와
설정값(`httprove_slo_target_ratio`)만 노출하고, 시간창 계산은 Prometheus에 맡깁니다. SLO 목표는
`httprove_slo_target_ratio`를 `1 - on(target) group_left() ...`로 조인해 타깃별로 DRY하게
파라미터화합니다(분모는 scalar-minus-vector라 matching modifier는 cross-metric 나눗셈에만 붙습니다).

메트릭 인벤토리 전체는 `../src/output/prom.rs` 모듈 주석, 설계는 `../docs/v0.3-metrics-spec.md`를
참고하세요.
