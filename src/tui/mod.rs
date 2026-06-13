//! 실시간 TUI 대시보드 (ratatui 0.30 + crossterm 0.29).
//!
//! ## 구조
//! - `app.rs` — 화면과 무관한 앱 상태(App): 결과 히스토리, StatsCollector,
//!   일시정지/종료 플래그.
//! - `ui.rs`  — App을 읽어 한 프레임을 그리는 순수 렌더 함수.
//! - `mod.rs` — 이벤트 루프: runner::spawn_probe_loop로 프로브를 돌리고,
//!   crossterm 키 이벤트와 mpsc 결과를 폴링하며 화면을 갱신한다.
//!
//! ## 이벤트 루프 (권장 구현)
//! - `ratatui::init()` / `ratatui::restore()` 사용 (panic hook 자동 처리).
//! - 터미널 이벤트는 `crossterm::event::poll(Duration::from_millis(50))` +
//!   `event::read()`. 결과 채널은 `rx.try_recv()` 루프로 비운다.
//!   (crossterm event-stream 피처 없이 동작해야 함 — 50ms 폴링이면 충분)
//! - 이 폴링 루프는 블로킹이므로 `tokio::task::spawn_blocking` 안에서 돌리고,
//!   run_tui는 async로 그 완료를 기다린다. (rx.try_recv는 동기 컨텍스트에서 호출 가능)
//! - count를 다 채워 rx가 닫히면 "finished" 표시 후 q 입력까지 화면 유지.
//!
//! ## 키 바인딩
//! - q / Esc / Ctrl-C: 종료 (cancel 후 정상 복원)
//! - space: 프로브 일시정지/재개 (handle.paused 토글, 모든 타깃 공통)
//! - r: 모든 타깃의 통계/히스토리 초기화
//! - tab: 다음 타깃 선택 (헤더/워터폴/통계 전환, 타깃 1개면 no-op)
//!
//! ## 레이아웃 (위→아래)
//! 1. 헤더 (높이 3, Block + 한 줄): [i/N](멀티 타깃) 선택 타깃 URL │ IP │
//!    HTTP 버전 │ TLS 버전 │ cert D-day(색상: 만료 빨강/임박 노랑/정상 초록) │
//!    상태(RUNNING/PAUSED/FINISHED)
//! 2. 레이턴시 차트 (가변 높이 2/3): 타깃마다 Dataset 하나씩, 인덱스 팔레트 색으로
//!    겹쳐 그림 (x=seq, y=total_ms, 타깃별 최근 120개 윈도우). 실패한 프로브는
//!    차트에서 제외하되 히스토리에 표시. 멀티 타깃이면 제목에 색상 범례.
//! 3. 중단 (높이 ~10, 좌우 분할, 선택 타깃 전용):
//!    - 좌: 마지막 성공 프로브의 단계별 워터폴 (단계명 + 막대 + ms,
//!      ms 값은 --warn 임계값 기준 노랑/빨강 강조)
//!    - 우: 통계 테이블 (행: 단계, 열: min/avg/p95/max) + sent/ok/fail/loss 한 줄
//! 4. 히스토리 (가변 높이 1/3): 전체 타깃 병합 히스토리를 ping 라인 스타일로
//!    한 줄씩 (멀티 타깃이면 "[short host]" prefix, 시각 + seq + 상태/에러 +
//!    단계별 시간, 최신이 아래), 실패는 빨강, 마지막 줄에 키 도움말.
//!
//! 색상: 단계별 고정 색 (dns=cyan, tcp=blue, tls=magenta, ttfb=yellow,
//! download=green, total=white) — ui.rs의 const로 정의.

mod app;
mod ui;

use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;
use tokio::sync::mpsc::error::TryRecvError;

use crate::runner::{self, ProbeLoopHandle};
use crate::types::ProbeConfig;

use self::app::App;

/// 터미널 이벤트 폴링 주기. 화면 갱신 최대 지연이기도 하다.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// TUI 실행. 종료(q)까지 블로킹. count=None이면 무한 프로브.
///
/// 멀티 타깃: cfgs마다 차트 색상을 달리해 한 차트에 겹쳐 그리고, tab으로
/// 헤더/워터폴/통계의 "선택 타깃"을 전환한다. warn 임계값은 워터폴의
/// ms 값 강조에 사용한다.
///
/// 종료 코드는 CLI 모드와 같은 계약을 따른다 (cli.rs 참조):
/// 0 = 전부 통과, 1 = 네트워크 실패 존재, 3 = expect 어설션 위반만 존재.
/// (r 키로 초기화하면 종료 시점의 누적 통계 기준.)
pub async fn run_tui(
    cfgs: Vec<ProbeConfig>,
    count: Option<u64>,
    interval: Duration,
    cert_warn_days: i64,
    warn: crate::types::WarnThresholds,
) -> anyhow::Result<ExitCode> {
    // 타깃 이름은 ProbeConfig.url 직렬화 — ProbeResult.target과 동일 문자열.
    let names: Vec<String> = cfgs.iter().map(|c| c.url.to_string()).collect();
    let handle = runner::spawn_probe_loop(cfgs, count, interval);
    let mut app = App::new(names, cert_warn_days, warn);

    // 블로킹 폴링 루프는 spawn_blocking에서 실행한다.
    // ratatui::init()이 panic hook으로 복원을 보장하고, 정상/에러 경로는
    // 클로저 안에서 restore()를 호출한다.
    let join = tokio::task::spawn_blocking(move || {
        let mut terminal = ratatui::init();
        let result = event_loop(&mut terminal, &mut app, handle);
        ratatui::restore();
        result.map(|()| {
            let net_failed = app.targets.iter().any(|t| t.stats.failed() > 0);
            let expect_failed = app.targets.iter().any(|t| t.stats.expect_failed() > 0);
            if net_failed {
                ExitCode::from(1)
            } else if expect_failed {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            }
        })
    })
    .await;

    match join {
        Ok(result) => result,
        Err(e) => {
            // 패닉 시 panic hook이 이미 복원했지만, 만일을 위해 한 번 더.
            ratatui::restore();
            Err(anyhow::anyhow!("tui task failed: {e}"))
        }
    }
}

/// 메인 이벤트 루프: 결과 채널 drain → 렌더 → 키 입력 처리 반복.
fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    mut handle: ProbeLoopHandle,
) -> anyhow::Result<()> {
    loop {
        // 결과 채널을 비운다. rx가 닫히면(count 소진) FINISHED로 전환하고
        // q 입력까지 화면을 유지한다.
        loop {
            match handle.rx.try_recv() {
                Ok(result) => app.update(result),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    app.finish();
                    break;
                }
            }
        }

        terminal.draw(|frame| ui::draw(frame, app))?;

        if !event::poll(POLL_INTERVAL)? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue; // resize 등은 다음 draw에서 자연 반영.
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            // q / Esc / Ctrl-C: 프로브 취소 후 종료.
            KeyCode::Char('q') | KeyCode::Esc => {
                handle.cancel.cancel();
                return Ok(());
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                handle.cancel.cancel();
                return Ok(());
            }
            // space: 일시정지/재개 (runner 플래그와 동기화, 헤더에 PAUSED 표시).
            KeyCode::Char(' ') => {
                if !app.finished {
                    app.paused = !app.paused;
                    handle.paused.store(app.paused, Ordering::Relaxed);
                }
            }
            // r: 모든 타깃 통계/히스토리 초기화.
            KeyCode::Char('r') => app.reset(),
            // tab: 다음 타깃 선택 (타깃 1개면 no-op).
            KeyCode::Tab => app.next_target(),
            _ => {}
        }
    }
}
