//! 프로브 반복 실행 루프 (멀티 타깃 지원).
//!
//! 동작 규칙:
//! - 타깃(ProbeConfig)마다 독립 태스크가 돌고, 결과는 공유 mpsc 채널 하나로 합쳐진다.
//! - seq는 타깃별로 0부터 독립적으로 증가한다. 같은 타깃의 프로브는 겹치지 않는다.
//! - 간격은 "시작 시각 기준": 다음 프로브는 이전 프로브 시작 + interval에 시작하되,
//!   프로브가 interval보다 오래 걸렸으면 즉시 시작한다.
//! - 멀티 타깃이면 i번째 타깃의 첫 프로브를 i * interval / N 만큼 늦춰
//!   출력이 인터리브되도록 한다.
//! - paused가 true인 동안은 새 프로브를 시작하지 않고 100ms 간격으로 재확인한다.
//! - count가 Some(n)이면 타깃마다 n회 후 종료, None이면 무한 (cancel로만 종료).
//! - cancel되면 즉시 종료. 모든 타깃 태스크가 끝나면 tx가 모두 drop되어 rx가 닫힌다.
//! - cfg.keep_alive면 KeepAliveProber(연결 재사용)로, 아니면 probe::probe로 실행한다.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::probe::{self, KeepAliveProber};
use crate::types::{ProbeConfig, ProbeResult};

/// 결과 채널 용량. 가득 차면 send().await로 백프레셔를 받는다.
const CHANNEL_CAPACITY: usize = 64;

/// paused 상태 재확인 주기.
const PAUSE_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// 프로브 루프 핸들. rx로 결과를 받고, cancel/paused로 제어한다.
pub struct ProbeLoopHandle {
    pub rx: mpsc::Receiver<ProbeResult>,
    pub cancel: CancellationToken,
    pub paused: Arc<AtomicBool>,
}

/// 타깃별 백그라운드 태스크로 프로브 루프를 시작한다.
pub fn spawn_probe_loop(
    cfgs: Vec<ProbeConfig>,
    count: Option<u64>,
    interval: Duration,
) -> ProbeLoopHandle {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let cancel = CancellationToken::new();
    let paused = Arc::new(AtomicBool::new(false));

    let n = cfgs.len().max(1) as u32;
    for (i, cfg) in cfgs.into_iter().enumerate() {
        let tx = tx.clone();
        let cancel = cancel.clone();
        let paused = Arc::clone(&paused);
        // 멀티 타깃 인터리브용 시작 오프셋.
        let start_offset = interval * (i as u32) / n;
        tokio::spawn(async move {
            probe_loop(cfg, count, interval, start_offset, tx, cancel, paused).await;
            // tx는 여기서 drop. 모든 타깃이 끝나면 rx가 닫힌다.
        });
    }
    // 원본 tx drop — 살아있는 송신자는 타깃 태스크들뿐.

    ProbeLoopHandle { rx, cancel, paused }
}

/// 한 타깃의 반복 루프 본체.
#[allow(clippy::too_many_arguments)] // 내부 함수, 호출처 1곳.
async fn probe_loop(
    cfg: ProbeConfig,
    count: Option<u64>,
    interval: Duration,
    start_offset: Duration,
    tx: mpsc::Sender<ProbeResult>,
    cancel: CancellationToken,
    paused: Arc<AtomicBool>,
) {
    // keep-alive 모드면 연결 상태를 유지하는 prober를 사용한다.
    let mut keepalive = cfg.keep_alive.then(|| KeepAliveProber::new(cfg.clone()));

    let mut seq: u64 = 0;
    // 다음 프로브 시작 예정 시각 (멀티 타깃 인터리브 오프셋 반영).
    let mut next_start = tokio::time::Instant::now() + start_offset;

    loop {
        // count 도달 시 종료.
        if let Some(n) = count
            && seq >= n
        {
            return;
        }

        // 시작 시각 기준 페이싱: 예정 시각이 이미 지났으면 즉시 통과한다.
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep_until(next_start) => {}
        }

        // paused 동안은 새 프로브를 시작하지 않고 주기적으로 재확인한다.
        while paused.load(Ordering::Relaxed) {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(PAUSE_POLL_INTERVAL) => {}
            }
        }

        let started = tokio::time::Instant::now();
        next_start = started + interval;

        // 프로브 실행. cancel되면 진행 중이라도 즉시 중단한다.
        let result = tokio::select! {
            _ = cancel.cancelled() => return,
            r = async {
                match &mut keepalive {
                    Some(prober) => prober.probe(seq).await,
                    None => probe::probe(&cfg, seq).await,
                }
            } => r,
        };

        // 채널이 가득 차면 백프레셔 대기. 수신측이 사라지면 종료한다.
        if tx.send(result).await.is_err() {
            return;
        }

        seq += 1;
    }
}
