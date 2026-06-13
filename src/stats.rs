//! 프로브 결과 누적 통계.
//!
//! - 성공한 프로브의 단계별 시간(= `ProbeResult::summed_timings()`, 리다이렉트 hop 합산)을
//!   기록한다. 실패한 프로브는 failed 카운트에만 반영한다.
//! - mean/stddev는 Welford 누적 알고리즘으로 전체 샘플에 대해 계산.
//! - 백분위(p50/p95/p99)는 단계별 링 버퍼(최근 `RING_CAP = 8192` 샘플)에서 계산.
//!   백분위는 nearest-rank 방식이면 충분하다.
//! - min/max는 누적 전체 기준.
//! - status_counts는 최종 hop의 상태 코드별 횟수.

use std::collections::{BTreeMap, VecDeque};

use serde::Serialize;

use crate::types::ProbeResult;

/// 백분위 계산용 링 버퍼 크기 (단계별 최근 샘플 수).
const RING_CAP: usize = 8192;

/// 통계 대상 단계.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Dns,
    Tcp,
    Tls,
    Ttfb,
    Download,
    Total,
}

impl Phase {
    pub const ALL: [Phase; 6] = [
        Phase::Dns,
        Phase::Tcp,
        Phase::Tls,
        Phase::Ttfb,
        Phase::Download,
        Phase::Total,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Phase::Dns => "dns",
            Phase::Tcp => "tcp",
            Phase::Tls => "tls",
            Phase::Ttfb => "ttfb",
            Phase::Download => "download",
            Phase::Total => "total",
        }
    }

    /// 내부 배열 인덱스.
    fn idx(self) -> usize {
        match self {
            Phase::Dns => 0,
            Phase::Tcp => 1,
            Phase::Tls => 2,
            Phase::Ttfb => 3,
            Phase::Download => 4,
            Phase::Total => 5,
        }
    }
}

/// 한 단계의 요약 통계 (밀리초).
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize)]
pub struct PhaseStats {
    pub count: u64,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub stddev: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
}

/// 한 단계의 누적기.
///
/// - mean/m2: Welford 누적 (전체 샘플 기준)
/// - min/max: 누적 전체 기준
/// - recent: 백분위 계산용 최근 샘플 링 버퍼 (cap = RING_CAP)
#[derive(Debug, Default)]
struct PhaseAccum {
    count: u64,
    mean: f64,
    m2: f64,
    min: f64,
    max: f64,
    recent: VecDeque<f64>,
}

impl PhaseAccum {
    /// 샘플 1개 반영.
    fn push(&mut self, v: f64) {
        if self.count == 0 {
            self.min = v;
            self.max = v;
        } else {
            self.min = self.min.min(v);
            self.max = self.max.max(v);
        }

        // Welford 누적.
        self.count += 1;
        let delta = v - self.mean;
        self.mean += delta / self.count as f64;
        self.m2 += delta * (v - self.mean);

        // 링 버퍼: 가득 차면 가장 오래된 샘플 제거.
        if self.recent.len() == RING_CAP {
            self.recent.pop_front();
        }
        self.recent.push_back(v);
    }

    /// 현재 시점 요약. 샘플이 없으면 None.
    fn snapshot(&self) -> Option<PhaseStats> {
        if self.count == 0 {
            return None;
        }

        // 백분위: 링 버퍼 정렬 사본에서 nearest-rank.
        let mut sorted: Vec<f64> = self.recent.iter().copied().collect();
        sorted.sort_by(|a, b| a.total_cmp(b));
        let pct = |p: f64| -> f64 {
            // nearest-rank: ceil(p/100 * n) 번째 값 (1-based).
            let n = sorted.len();
            let rank = ((p / 100.0) * n as f64).ceil() as usize;
            sorted[rank.clamp(1, n) - 1]
        };

        Some(PhaseStats {
            count: self.count,
            min: self.min,
            max: self.max,
            mean: self.mean,
            // 모집단 표준편차 (ping의 mdev와 동일 계열).
            stddev: (self.m2 / self.count as f64).sqrt(),
            p50: pct(50.0),
            p95: pct(95.0),
            p99: pct(99.0),
        })
    }
}

/// 프로브 결과 수집기. CLI ping 모드와 TUI가 공용으로 사용한다.
#[derive(Debug, Default)]
pub struct StatsCollector {
    sent: u64,
    succeeded: u64,
    failed: u64,
    /// 네트워크는 성공했지만 --expect 어설션을 위반한 프로브 수.
    expect_failed: u64,
    /// Phase::idx() 순서의 단계별 누적기.
    phases: [PhaseAccum; 6],
    status_counts: BTreeMap<u16, u64>,
}

impl StatsCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// 프로브 결과 1건 반영.
    pub fn record(&mut self, result: &ProbeResult) {
        self.sent += 1;

        // 실패한 프로브는 failed 카운트에만 반영 (단계 통계/상태 코드 오염 방지).
        if !result.is_success() {
            self.failed += 1;
            return;
        }
        self.succeeded += 1;
        if !result.expect_failures.is_empty() {
            self.expect_failed += 1;
        }

        if let Some(status) = result.status() {
            *self.status_counts.entry(status).or_insert(0) += 1;
        }

        // 리다이렉트 hop 합산 시간 기준으로 단계별 기록.
        let t = result.summed_timings();
        if let Some(v) = t.dns_ms {
            self.phases[Phase::Dns.idx()].push(v);
        }
        // keep-alive 재사용 프로브는 연결 단계가 없다: dns/tls는 None이라 자연히
        // 빠지지만 tcp_ms는 Option이 아니어서(항상 0.0) 여기서 걸러야 한다 —
        // 안 거르면 재사용 프로브마다 0.0이 쌓여 TCP 분포(min/평균/백분위)가 무너진다.
        let conn_reused = !result.hops.is_empty() && result.hops.iter().all(|h| h.reused_conn);
        if !conn_reused {
            self.phases[Phase::Tcp.idx()].push(t.tcp_ms);
        }
        if let Some(v) = t.tls_ms {
            self.phases[Phase::Tls.idx()].push(v);
        }
        self.phases[Phase::Ttfb.idx()].push(t.ttfb_ms);
        self.phases[Phase::Download.idx()].push(t.download_ms);
        self.phases[Phase::Total.idx()].push(t.total_ms);
    }

    /// 보낸 프로브 수 (성공 + 실패).
    pub fn sent(&self) -> u64 {
        self.sent
    }

    pub fn succeeded(&self) -> u64 {
        self.succeeded
    }

    pub fn failed(&self) -> u64 {
        self.failed
    }

    /// 네트워크 성공 + 어설션 위반 프로브 수.
    pub fn expect_failed(&self) -> u64 {
        self.expect_failed
    }

    /// 실패율 % (sent == 0이면 0.0).
    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            self.failed as f64 / self.sent as f64 * 100.0
        }
    }

    /// 단계별 통계. 해당 단계 샘플이 하나도 없으면 None (예: http 대상의 tls).
    pub fn phase_stats(&self, phase: Phase) -> Option<PhaseStats> {
        self.phases[phase.idx()].snapshot()
    }

    /// 최종 hop 상태 코드별 횟수.
    pub fn status_counts(&self) -> &BTreeMap<u16, u64> {
        &self.status_counts
    }

    /// 모든 누적치 초기화 (TUI의 r 키).
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use super::*;
    use crate::types::{ErrorPhase, HopResult, PhaseTimings, ProbeError, ProbeResult};

    /// 성공 프로브 생성 헬퍼. https 여부에 따라 dns/tls 단계 유무가 갈린다.
    fn ok_probe(seq: u64, total: f64, with_dns_tls: bool) -> ProbeResult {
        let timings = PhaseTimings {
            dns_ms: with_dns_tls.then_some(1.0),
            tcp_ms: 2.0,
            tls_ms: with_dns_tls.then_some(3.0),
            ttfb_ms: 4.0,
            download_ms: 5.0,
            total_ms: total,
        };
        ProbeResult {
            target: "http://example.com/".to_string(),
            seq,
            timestamp: Utc::now(),
            hops: vec![HopResult {
                url: "http://example.com/".to_string(),
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 80,
                reused_conn: false,
                local_addr: None,
                resolved_ips: vec![],
                http_version: "HTTP/1.1".to_string(),
                status: 200,
                timings,
                tls: None,
                cert_chain: vec![],
                response_headers: vec![],
                body_bytes: 0,
                redirect_to: None,
            }],
            error: None,
            expect_failures: vec![],
            total_ms: total,
        }
    }

    /// 실패 프로브 생성 헬퍼. hop이 일부 진행된 상태의 실패를 흉내낸다.
    fn failed_probe(seq: u64) -> ProbeResult {
        let mut p = ok_probe(seq, 999.0, true);
        p.error = Some(ProbeError {
            phase: ErrorPhase::Tcp,
            message: "connection refused".to_string(),
            timed_out: false,
        });
        p
    }

    #[test]
    fn empty_collector() {
        let stats = StatsCollector::new();
        assert_eq!(stats.sent(), 0);
        assert_eq!(stats.succeeded(), 0);
        assert_eq!(stats.failed(), 0);
        assert_eq!(stats.loss_pct(), 0.0);
        assert!(stats.status_counts().is_empty());
        for phase in Phase::ALL {
            assert!(stats.phase_stats(phase).is_none(), "{}", phase.label());
        }
    }

    #[test]
    fn single_sample() {
        let mut stats = StatsCollector::new();
        stats.record(&ok_probe(0, 15.0, false));

        let total = stats.phase_stats(Phase::Total).unwrap();
        assert_eq!(total.count, 1);
        assert_eq!(total.min, 15.0);
        assert_eq!(total.max, 15.0);
        assert_eq!(total.mean, 15.0);
        assert_eq!(total.stddev, 0.0);
        assert_eq!(total.p50, 15.0);
        assert_eq!(total.p95, 15.0);
        assert_eq!(total.p99, 15.0);

        // http 대상: dns/tls 샘플이 없으므로 None.
        assert!(stats.phase_stats(Phase::Dns).is_none());
        assert!(stats.phase_stats(Phase::Tls).is_none());
        assert_eq!(stats.status_counts().get(&200), Some(&1));
    }

    #[test]
    fn known_percentiles() {
        let mut stats = StatsCollector::new();
        // total = 1.0 ..= 100.0 → nearest-rank 백분위는 정확히 그 순위 값.
        for i in 1..=100u64 {
            stats.record(&ok_probe(i, i as f64, true));
        }

        let total = stats.phase_stats(Phase::Total).unwrap();
        assert_eq!(total.count, 100);
        assert_eq!(total.min, 1.0);
        assert_eq!(total.max, 100.0);
        assert!((total.mean - 50.5).abs() < 1e-9);
        assert_eq!(total.p50, 50.0);
        assert_eq!(total.p95, 95.0);
        assert_eq!(total.p99, 99.0);

        // https 프로브였으므로 dns/tls 통계도 존재.
        assert_eq!(stats.phase_stats(Phase::Dns).unwrap().count, 100);
        assert_eq!(stats.phase_stats(Phase::Tls).unwrap().count, 100);
        assert_eq!(stats.status_counts().get(&200), Some(&100));
    }

    #[test]
    fn reset_clears_everything() {
        let mut stats = StatsCollector::new();
        stats.record(&ok_probe(0, 10.0, true));
        stats.record(&failed_probe(1));
        assert_eq!(stats.sent(), 2);

        stats.reset();
        assert_eq!(stats.sent(), 0);
        assert_eq!(stats.succeeded(), 0);
        assert_eq!(stats.failed(), 0);
        assert_eq!(stats.loss_pct(), 0.0);
        assert!(stats.status_counts().is_empty());
        assert!(stats.phase_stats(Phase::Total).is_none());
    }

    #[test]
    fn failed_probes_do_not_pollute_phase_stats() {
        let mut stats = StatsCollector::new();
        stats.record(&ok_probe(0, 10.0, false));
        stats.record(&failed_probe(1)); // total 999.0이지만 통계에 반영되면 안 됨.
        stats.record(&failed_probe(2));

        assert_eq!(stats.sent(), 3);
        assert_eq!(stats.succeeded(), 1);
        assert_eq!(stats.failed(), 2);
        assert!((stats.loss_pct() - 200.0 / 3.0).abs() < 1e-9);

        let total = stats.phase_stats(Phase::Total).unwrap();
        assert_eq!(total.count, 1);
        assert_eq!(total.max, 10.0);

        // 실패 프로브의 hop 상태 코드도 집계되지 않는다.
        assert_eq!(stats.status_counts().get(&200), Some(&1));
    }

    #[test]
    fn reused_conn_probes_do_not_pollute_tcp_stats() {
        let mut stats = StatsCollector::new();
        // 첫 연결 프로브: tcp 샘플 1개 (2.0ms).
        stats.record(&ok_probe(0, 10.0, true));
        // keep-alive 재사용 프로브: 연결 단계 없음 (tcp_ms는 형식상 0.0).
        let mut reused = ok_probe(1, 8.0, false);
        reused.hops[0].reused_conn = true;
        reused.hops[0].timings.tcp_ms = 0.0;
        stats.record(&reused);

        let tcp = stats.phase_stats(Phase::Tcp).unwrap();
        assert_eq!(tcp.count, 1);
        assert_eq!(tcp.min, 2.0); // 0.0이 섞이면 min이 0으로 고정된다.
        // ttfb/total 등 나머지 단계는 재사용 프로브도 정상 집계된다.
        assert_eq!(stats.phase_stats(Phase::Total).unwrap().count, 2);
    }

    #[test]
    fn ring_buffer_caps_percentile_window_but_not_min_max() {
        let mut acc = PhaseAccum::default();
        // 0.0 하나를 넣고, 그 뒤 RING_CAP개의 100.0으로 밀어낸다.
        acc.push(0.0);
        for _ in 0..RING_CAP {
            acc.push(100.0);
        }
        assert_eq!(acc.recent.len(), RING_CAP);

        let s = acc.snapshot().unwrap();
        // 누적 min은 링 버퍼에서 밀려나도 유지.
        assert_eq!(s.min, 0.0);
        assert_eq!(s.max, 100.0);
        assert_eq!(s.count, RING_CAP as u64 + 1);
        // 백분위 창은 최근 샘플(전부 100.0)만 반영.
        assert_eq!(s.p50, 100.0);
        assert_eq!(s.p99, 100.0);
    }
}
