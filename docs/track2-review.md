<!-- /xm:op 트랙2 검토 (Workflow 4-agent, 2026-06-19). 원천: .xm/op/brainstorm-2026-06-19-httprove-feature-metrics.json -->

# httprove 트랙2 검토 결론 (B3/B4/B8)

## 결론 한 줄
트랙2는 **대폭 축소(reduce)**한다 — 3개 중 시계열/슬라이딩 윈도우를 요구하는 부분은 전부 무상태 스냅샷 모델과 충돌하거나 기존 카운터+PromQL과 중복이므로 버리고, **모델에 정합하는 무상태 잔여물만 골라(누적 Apdex 2카운터, SLO 목표 게이지, stddev stat 1줄)** 가볍게 채택한다.

## 아이디어별 판정 (표)

| ID | 제목 | 권고 | 핵심 이유(한 줄) | effort |
|----|------|------|------------------|--------|
| B3 | Availability ratio + Apdex | **부분 채택** | availability는 기존 2카운터로 100% 중복(drop), Apdex는 누적 2카운터형 신규 latency 체감 스칼라(채택) | S |
| B4 | SLO error-budget burn-rate (`--slo`) | **대폭 축소 채택** | burn/budget은 시계열 필요+재시작 시 소실로 drop, SLO 목표값만 무상태 라벨 게이지로 노출 | S |
| B8 | EWMA + z-score adaptive outlier | **drop** (단, stddev 패치는 별건으로) | 누적 z는 장기 무뎌짐+콜드스타트 과민, EWMA는 자체 시간축+재시작 소실, 무득표 | S(파생만) |

## 무엇을 만들고 무엇을 버리나

### 채택 (build_modified — 전부 무상태 형태로)

**1. Apdex (B3 후반) — 누적 카운터 2개**
- 메트릭: `httprove_apdex_satisfied_total` (counter), `httprove_apdex_tolerating_total` (counter)
- 형태: **슬라이딩 윈도우 금지, 단조 카운터로만.** B7 throughput(stats.rs:248)과 동형 — record() 내 `self.phases[Total].push(t.total_ms)`(stats.rs:241) 인접 지점에서 성공 프로브에 한해 `satisfied += (total_ms<=T)`, `tolerating += (T<total_ms<=4T)`. `reset()`(stats.rs:316)이 `*self=Self::new()`라 자동 초기화.
- 임계 전달: T를 CLI(`--apdex-threshold`)로 받아 collector 필드로 보관하거나 record 시그니처에 주입 — **이게 유일한 설계 마찰점**(B7과 달리 외부 파라미터 의존). `StatsCollector::new()`가 무인자라 둘 중 하나를 골라야 함. T 미설정이면 메트릭 전체 생략(push_section의 빈 lines 패턴, prom.rs:86).
- 분모 명시 필수: HELP에 `sent 기준`인지 `succeeded 기준`인지 박을 것(전자=가용성+latency 혼합, 후자=순수 latency). 이걸 안 적으면 PromQL 작성자가 오해.
- 소비: `(rate(apdex_satisfied[5m])+rate(apdex_tolerating[5m])/2)/rate(httprove_probes_total[5m])`. 분모는 기존 `probes_total` 재사용.
- **왜 신규인가**: phase_milliseconds는 summary 게이지(min/mean/p50/p95/p99/max, prom.rs:58 직접 확인)지 le-bucket 히스토그램이 아니라, `histogram_quantile`로도 'T 이하 비율'을 못 뽑는다. 서버측에서만 계산 가능한 유일한 latency 체감 스칼라.

**2. SLO 목표값 (B4 잔여물) — 무상태 게이지**
- 메트릭: `httprove_slo_target_ratio{target}` (gauge, 예: `0.999`)
- 형태: 측정값이 아니라 **설정값** — `--slo` 플래그를 `TargetMetrics`(prom.rs:45-55)에 `slo: Option<f64>`로 싣고 verdict_state 블록 뒤에 push_section 한 블록. StatsCollector 무수정, 시간창 무관, 재시작 무관.
- CLI 검증 필수: 0.999 vs 99.9 vs 99.9% 단위 혼동을 강제 차단(`--cert-warn` 검증 헬퍼 스타일). 안 하면 burn 룰 상수가 1000배 틀어짐.
- **왜 신규인가**: SLO 목표 상수 `(1-SLO)`는 메트릭 어디에도 없어 지금은 PromQL 룰에 손으로 박아야 한다. 게이지로 노출하면 타깃별로 룰을 DRY하게 파라미터화 — 합성 프로버만 아는 '이 타깃의 SLO 의도'를 메트릭화.

**3. (별건) stddev stat 추가 — 트랙1 일관성 패치**
- B8 자체가 아니라, B8 검토가 발견한 **기존 버그**: stddev는 이미 계산되어 텍스트/TUI엔 나오지만(stats.rs:140) prom의 `STAT_ORDER`(prom.rs:58, 직접 확인 — `["min","mean","p50","p95","p99","max"]`)에서 누락. text와 prom 출력이 불일치.
- 수정: `STAT_ORDER`에 `"stddev"` 추가 + phase 게이지 zip 지점(prom.rs:175-176)에 끼움. 이미 계산된 값이라 1줄급.

### 버림 (drop)

**Availability ratio (B3 전반) — 100% 중복.** `httprove_probes_total`(=sent, prom.rs:113-147)와 `httprove_probe_failures_total`(=failed)로 완전 유도. 어설션 포함 버전도 `httprove_expect_failures_total`로 유도됨. 게이지화는 고정 윈도우 강요 + 무상태 모델 위반이라 순손실.
- 대신: `1 - rate(httprove_probe_failures_total[5m]) / rate(httprove_probes_total[5m])`

**Burn-rate / error_budget_remaining (B4 원형) — 모델 충돌.** 시간창 rate가 핵심인데 StatsCollector는 시계열 미보관. since-process-start 누적 실패율은 burn 정의(짧은 창의 급격한 소진)와 정반대 — exporter가 수주 떠 있으면 최근 장애가 과거 성공에 희석돼 신호가 죽음. 재시작 시 budget이 100%로 되살아나 거짓 안심(false-OK).
- 대신(단기 burn): `(rate(httprove_probe_failures_total[5m]) / rate(httprove_probes_total[5m])) / (1 - 0.999)`
- 대신(28일 budget): `1 - (increase(httprove_probe_failures_total[28d]) / increase(httprove_probes_total[28d])) / (1 - 0.999)` — Prometheus가 counter-reset까지 자동 보정(도구가 자체 윈도우로 하면 이 보정을 잃음).

**EWMA + z-score (B8 전체) — 무득표, drop.** 누적 z는 Welford가 안 decay해 장기 무뎌짐 + 콜드스타트 stddev≈0 과민(0 나눗셈 위험). EWMA는 자체 시간축(프로브 도착 순서, wall-time 아님)+재시작/reset 소실. 유일 고객인 cron 사용자는 run당 샘플 1개라 EWMA 무의미하고 이미 warn 임계/expect_ttfb/verdict로 커버됨.
- 대신(윈도우 z-score): `(phase_mean - avg_over_time(phase_mean[1h])) / stddev_over_time(phase_mean[1h]) > 3` — 저장된 시계열로 재시작에도 견고.

## 권고 실행안

**트랙2를 한다면: 단일 작은 PR, 순서대로.**

1. **stddev 일관성 패치 먼저** (트랙1 버그 수정, 독립적·무위험): `STAT_ORDER`에 stddev 추가(prom.rs:58 + zip 175-176). 이걸 먼저 머지하면 B8 검토가 짚은 text/prom 불일치가 닫히고, 윈도우 z-score PromQL 작성도 쉬워진다.
2. **SLO 목표 게이지** (StatsCollector 무수정, effort S): `--slo` + `TargetMetrics.slo` + push_section 1블록 + CLI 단위 검증.
3. **Apdex 누적 2카운터** (마찰점 있는 것 마지막, effort S): `--apdex-threshold` + collector 필드(또는 record 시그니처) 결정 + 2카운터 + getter 2개 + push_section 2섹션. **구현 시 명세 원문의 'sliding window'를 반드시 cumulative로 재해석**할 것 — 안 그러면 reset/재시작/이중 시간축 버그를 그대로 들여온다.

세 항목 모두 effort S이고 render 시그니처 불변이라 한 PR로 묶어도 됨. 다만 1번은 성격이 다르므로(트랙1 버그 수정) 별 커밋으로 분리.

**솔직한 평가**: 트랙2의 원래 야심(SLO·burn·adaptive 신호)은 대부분 트랙1 카운터 + 표준 PromQL recording rule로 이미 충족되거나, 무상태 모델과 충돌한다. 순가치는 (a) Apdex 절반, (b) SLO 목표 라벨, (c) stddev 1줄 — 합쳐도 작은 PR 하나다. 트랙2를 '트랙'으로 부를 만큼의 무게는 없다.

**대안 권고**: 별도 트랙으로 추진할 가치가 있는 건 트랙2가 아니라, 이미 머지된 트랙1 메트릭의 **소비 경험을 완성하는 방향**(예: 동봉 Grafana 대시보드 JSON + 표준 recording-rule/alert 룰 번들). burn-rate·availability·z-score를 도구에 박는 대신 "PromQL로 어떻게 뽑는지"를 룰 파일로 제공하면, 위 drop 항목들의 진짜 사용자 욕구를 무상태 모델을 깨지 않고 충족한다. 이게 트랙2 잔여물 3개보다 ROI가 높은 다음 작업이다.

(검증: stats.rs:241/248/271-277/316, prom.rs:45-55/58/86 직접 확인 — JSON 검토의 핵심 라인 인용은 모두 코드와 일치.)
