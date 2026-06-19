# httprove 메트릭 소비 번들

httprove가 `--prom`/`--listen`으로 노출하는 메트릭을 Prometheus + Grafana에서 바로 쓰기 위한
recording 룰·alert 룰·대시보드입니다. httprove는 **무상태 스냅샷 익스포터**라 시간축
(rate·burn-rate·availability·z-score)은 Prometheus가 계산합니다 — 그 계산을 이 번들이 담습니다.

## 파일

| 파일 | 내용 |
|---|---|
| `prometheus-recording-rules.yml` | availability · strict-availability · Apdex · SLO burn-rate(5m/30m/1h/6h) · error-budget(28d) · TTFB p95 z-score — 9개 룰 |
| `prometheus-alerts.yml` | TargetDown · FleetTargetsDown · CertExpiringSoon/Expired · CertChainIncomplete · TLSDowngrade · SLOFastBurn/SlowBurn · ApdexDegraded · LatencyAnomaly · DNSAnswerChanged — 11개 알림 |
| `grafana-dashboard.json` | Fleet / Latency / TLS·Cert / Verdict / Connection / DNS / SLO — 8행 25패널 (schemaVersion 39, datasource 변수 `${DS_PROMETHEUS}`) |

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

## 설계 메모

이 번들은 트랙2 검토(`../docs/track2-review.md`)의 결론을 구현합니다: burn-rate·availability·
error-budget·z-score는 **도구에 박는 대신 룰로** 만듭니다. httprove는 무상태 카운터·게이지와
설정값(`httprove_slo_target_ratio`)만 노출하고, 시간창 계산은 Prometheus에 맡깁니다. SLO 목표는
`httprove_slo_target_ratio`를 `1 - on(target) group_left() ...`로 조인해 타깃별로 DRY하게
파라미터화합니다(분모는 scalar-minus-vector라 matching modifier는 cross-metric 나눗셈에만 붙습니다).

메트릭 인벤토리 전체는 `../src/output/prom.rs` 모듈 주석, 설계는 `../docs/v0.3-metrics-spec.md`를
참고하세요.
