//! TUI 렌더링 — App 상태를 읽어 한 프레임을 그린다 (mod.rs의 레이아웃 스펙 참고).
//!
//! 멀티 타깃: 차트는 모든 타깃을 인덱스 팔레트 색으로 겹쳐 그리고,
//! 헤더/워터폴/통계는 선택 타깃만 표시한다. 히스토리는 병합 스트림에
//! "[short host]" prefix를 붙인다 (타깃 1개면 생략).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Axis, Block, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table};

use crate::stats::Phase;
use crate::types::WarnLevel;

use super::app::App;

// 단계별 고정 색 (mod.rs 스펙).
const COLOR_DNS: Color = Color::Cyan;
const COLOR_TCP: Color = Color::Blue;
const COLOR_TLS: Color = Color::Magenta;
const COLOR_TTFB: Color = Color::Yellow;
const COLOR_DOWNLOAD: Color = Color::Green;
const COLOR_TOTAL: Color = Color::White;
const COLOR_DIM: Color = Color::DarkGray;

/// 타깃 인덱스별 차트/범례 색 팔레트 (인덱스 % 8로 순환).
const TARGET_PALETTE: [Color; 8] = [
    Color::White,
    Color::Cyan,
    Color::Magenta,
    Color::Yellow,
    Color::Green,
    Color::Blue,
    Color::LightRed,
    Color::LightCyan,
];

/// 차트 x축 슬라이딩 윈도우 크기 (타깃별 최근 seq 개수).
const CHART_WINDOW: u64 = 120;

const fn phase_color(phase: Phase) -> Color {
    match phase {
        Phase::Dns => COLOR_DNS,
        Phase::Tcp => COLOR_TCP,
        Phase::Tls => COLOR_TLS,
        Phase::Ttfb => COLOR_TTFB,
        Phase::Download => COLOR_DOWNLOAD,
        Phase::Total => COLOR_TOTAL,
    }
}

/// 타깃 인덱스 → 팔레트 색 (순환).
const fn target_color(index: usize) -> Color {
    TARGET_PALETTE[index % TARGET_PALETTE.len()]
}

/// `--warn` 임계값 대비 ms 값의 강조 스타일 (CLI와 동일 규칙: 1x 노랑 / 2x 빨강).
fn warn_style(value: f64, threshold: Option<f64>) -> Style {
    match WarnLevel::of(value, threshold) {
        WarnLevel::Crit => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        WarnLevel::Warn => Style::new().fg(Color::Yellow),
        WarnLevel::Ok => Style::new(),
    }
}

/// 한 프레임 전체를 그린다.
pub fn draw(frame: &mut Frame, app: &App) {
    // 위→아래: 헤더(3) / 차트(가변 2) / 중단(10) / 히스토리(가변 1).
    let [header_area, chart_area, middle_area, history_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(2),
        Constraint::Length(10),
        Constraint::Fill(1),
    ])
    .areas(frame.area());

    draw_header(frame, app, header_area);
    draw_chart(frame, app, chart_area);

    let [waterfall_area, stats_area] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
            .areas(middle_area);
    draw_waterfall(frame, app, waterfall_area);
    draw_stats(frame, app, stats_area);

    draw_history(frame, app, history_area);
}

/// 헤더: [i/N](멀티 타깃) 선택 타깃 URL │ IP │ HTTP 버전 │ TLS 버전 │ cert D-day │ 상태.
fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let sep = Span::styled(" │ ", Style::new().fg(COLOR_DIM));
    let mut spans = Vec::new();

    // 멀티 타깃이면 [i/N] 인디케이터 (선택 타깃 팔레트 색).
    if app.targets.len() > 1 {
        spans.push(Span::styled(
            format!("[{}/{}] ", app.selected + 1, app.targets.len()),
            Style::new()
                .fg(target_color(app.selected))
                .add_modifier(Modifier::BOLD),
        ));
    }

    let selected = app.selected_target();
    let name = selected.map(|t| t.name.as_str()).unwrap_or("-");
    spans.push(Span::styled(
        name.to_string(),
        Style::new().add_modifier(Modifier::BOLD),
    ));

    let last_success = selected.and_then(|t| t.last_success.as_ref());
    let final_hop = last_success.and_then(|r| r.final_hop());
    match final_hop {
        Some(hop) => {
            spans.push(sep.clone());
            spans.push(Span::raw(hop.ip.to_string()));
            spans.push(sep.clone());
            spans.push(Span::raw(hop.http_version.clone()));
            spans.push(sep.clone());
            match &hop.tls {
                Some(tls) => spans.push(Span::raw(tls.version.clone())),
                None => spans.push(Span::styled("no TLS", Style::new().fg(COLOR_DIM))),
            }
        }
        None => {
            spans.push(sep.clone());
            spans.push(Span::styled("waiting...", Style::new().fg(COLOR_DIM)));
        }
    }

    // cert D-day: 만료 빨강 / 임박 노랑 / 정상 초록.
    spans.push(sep.clone());
    match last_success.and_then(|r| r.leaf_cert()) {
        Some(cert) => {
            let days = cert.days_remaining;
            let (text, color) = if days < 0 {
                (format!("cert expired {}d ago", -days), Color::Red)
            } else if days <= app.cert_warn_days {
                (format!("cert D-{days}"), Color::Yellow)
            } else {
                (format!("cert D-{days}"), Color::Green)
            };
            spans.push(Span::styled(text, Style::new().fg(color)));
        }
        None => spans.push(Span::styled("no cert", Style::new().fg(COLOR_DIM))),
    }

    let (state_text, state_color) = if app.finished {
        ("FINISHED", Color::Cyan)
    } else if app.paused {
        ("PAUSED", Color::Yellow)
    } else {
        ("RUNNING", Color::Green)
    };
    spans.push(sep);
    spans.push(Span::styled(
        state_text,
        Style::new().fg(state_color).add_modifier(Modifier::BOLD),
    ));

    let paragraph = Paragraph::new(Line::from(spans)).block(Block::bordered().title("httprove"));
    frame.render_widget(paragraph, area);
}

/// 레이턴시 꺾은선 차트: 타깃마다 Dataset 하나, x=seq(타깃별 최근 CHART_WINDOW개
/// 윈도우), y=total_ms. 멀티 타깃이면 제목에 short label 색상 범례.
fn draw_chart(frame: &mut Frame, app: &App, area: Rect) {
    let n = app.targets.len();

    // 타깃별 최신 seq (히스토리 기준, 실패 포함 — 윈도우 기준점).
    let mut latest: Vec<Option<u64>> = vec![None; n];
    for r in &app.history {
        if let Some(i) = app.target_index(&r.target) {
            latest[i] = Some(latest[i].map_or(r.seq, |s| s.max(r.seq)));
        }
    }
    let window_start: Vec<u64> = latest
        .iter()
        .map(|l| l.unwrap_or(0).saturating_sub(CHART_WINDOW - 1))
        .collect();

    // 타깃별 성공 결과 포인트 수집. 실패 프로브는 차트에서 제외 (히스토리에서 확인).
    let mut points: Vec<Vec<(f64, f64)>> = vec![Vec::new(); n];
    for r in &app.history {
        if !r.is_success() {
            continue;
        }
        if let Some(i) = app.target_index(&r.target)
            && r.seq >= window_start[i]
        {
            points[i].push((r.seq as f64, r.total_ms));
        }
    }

    // 축 범위: 데이터가 있는 타깃 윈도우들의 합집합.
    let seq_min = (0..n)
        .filter(|&i| latest[i].is_some())
        .map(|i| window_start[i])
        .min()
        .unwrap_or(0);
    let seq_max = (0..n)
        .filter_map(|i| latest[i])
        .max()
        .unwrap_or(0)
        .max(seq_min + 1);
    let x_min = seq_min as f64;
    let x_max = seq_max as f64;
    let y_peak = points.iter().flatten().map(|p| p.1).fold(0.0_f64, f64::max);
    // 비어 있거나 0이면 안전한 기본 범위.
    let y_max = if y_peak > 0.0 { y_peak * 1.2 } else { 100.0 };

    // Dataset은 슬라이스를 빌리므로 points 수집 후 별도 패스로 생성한다.
    // name은 지정하지 않아 내장 범례를 숨기고, 범례는 블록 제목으로 표시한다.
    let datasets: Vec<Dataset> = points
        .iter()
        .enumerate()
        .filter(|(_, pts)| !pts.is_empty())
        .map(|(i, pts)| {
            Dataset::default()
                .data(pts.as_slice())
                .marker(symbols::Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::new().fg(target_color(i)))
        })
        .collect();

    let x_axis = Axis::default()
        .style(Style::new().fg(COLOR_DIM))
        .bounds([x_min, x_max])
        .labels([format!("#{seq_min}"), format!("#{seq_max}")]);
    let y_axis = Axis::default()
        .style(Style::new().fg(COLOR_DIM))
        .bounds([0.0, y_max])
        .labels([
            "0".to_string(),
            format!("{:.0}", y_max / 2.0),
            format!("{y_max:.0}"),
        ]);

    // 멀티 타깃이면 제목에 "타깃=색" 범례 (short label을 해당 팔레트 색으로 표시).
    let title: Line = if n > 1 {
        let mut spans = vec![Span::raw("latency (total ms) ")];
        for (i, target) in app.targets.iter().enumerate() {
            if i > 0 {
                spans.push(Span::styled(" ", Style::new().fg(COLOR_DIM)));
            }
            spans.push(Span::styled(
                target.short.clone(),
                Style::new().fg(target_color(i)),
            ));
        }
        Line::from(spans)
    } else {
        Line::from("latency (total ms)")
    };

    let chart = Chart::new(datasets)
        .block(Block::bordered().title(title))
        .x_axis(x_axis)
        .y_axis(y_axis);
    frame.render_widget(chart, area);
}

/// 좌측 중단: 선택 타깃의 마지막 성공 프로브 단계별 워터폴 (색 막대 + ms,
/// ms 값은 --warn 임계값 기준 노랑/빨강 강조).
fn draw_waterfall(frame: &mut Frame, app: &App, area: Rect) {
    let selected = app.selected_target();
    let short = selected.map(|t| t.short.as_str()).unwrap_or("-");

    let Some(result) = selected.and_then(|t| t.last_success.as_ref()) else {
        let paragraph = Paragraph::new(Line::styled(
            "waiting for first successful probe...",
            Style::new().fg(COLOR_DIM),
        ))
        .block(Block::bordered().title(format!("waterfall {short}")));
        frame.render_widget(paragraph, area);
        return;
    };

    let title = match result.status() {
        Some(status) => format!("waterfall {short} #{} (HTTP {status})", result.seq),
        None => format!("waterfall {short} #{}", result.seq),
    };
    let timings = result.summed_timings();
    // (라벨, 값, 막대 색, warn 임계값) — None 단계는 행 생략.
    let rows: [(&str, Option<f64>, Color, Option<f64>); 6] = [
        ("dns", timings.dns_ms, COLOR_DNS, app.warn.dns),
        ("tcp", Some(timings.tcp_ms), COLOR_TCP, app.warn.tcp),
        ("tls", timings.tls_ms, COLOR_TLS, app.warn.tls),
        ("ttfb", Some(timings.ttfb_ms), COLOR_TTFB, app.warn.ttfb),
        (
            "download",
            Some(timings.download_ms),
            COLOR_DOWNLOAD,
            app.warn.download,
        ),
        ("total", Some(timings.total_ms), COLOR_TOTAL, app.warn.total),
    ];

    // 막대 폭: 라벨(8) + 여백 + ms 표기(약 12)를 제외한 나머지.
    let inner_width = area.width.saturating_sub(2) as usize;
    let max_bar = inner_width.saturating_sub(22).max(4);
    let scale = timings.total_ms.max(f64::EPSILON);

    let lines: Vec<Line> = rows
        .iter()
        .filter_map(|(label, value, color, threshold)| {
            let v = (*value)?;
            let ratio = (v / scale).clamp(0.0, 1.0);
            let bar_len = (ratio * max_bar as f64).round() as usize;
            Some(Line::from(vec![
                Span::raw(format!("{label:>8} ")),
                Span::styled("█".repeat(bar_len), Style::new().fg(*color)),
                // ms 값: 임계값 초과 시 노랑(1x)/빨강(2x) 강조 (CLI와 동일).
                Span::styled(format!(" {v:>8.1} ms"), warn_style(v, *threshold)),
            ]))
        })
        .collect();

    let paragraph = Paragraph::new(lines).block(Block::bordered().title(title));
    frame.render_widget(paragraph, area);
}

/// 우측 중단: 선택 타깃의 단계별 min/avg/p95/max 테이블 + sent/ok/fail/loss 한 줄.
fn draw_stats(frame: &mut Frame, app: &App, area: Rect) {
    let selected = app.selected_target();
    let short = selected.map(|t| t.short.as_str()).unwrap_or("-");
    let block = Block::bordered().title(format!("stats {short}"));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(target) = selected else {
        return; // 방어적: 타깃 없으면 빈 블록만.
    };

    let [table_area, counts_area] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);

    let header = Row::new(["phase", "min", "avg", "p95", "max"])
        .style(Style::new().add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = Phase::ALL
        .iter()
        .map(|&phase| {
            let label = Cell::from(phase.label()).style(Style::new().fg(phase_color(phase)));
            match target.stats.phase_stats(phase) {
                Some(s) => Row::new(vec![
                    label,
                    num_cell(s.min),
                    num_cell(s.mean),
                    num_cell(s.p95),
                    num_cell(s.max),
                ]),
                None => Row::new(vec![
                    label,
                    dash_cell(),
                    dash_cell(),
                    dash_cell(),
                    dash_cell(),
                ]),
            }
        })
        .collect();
    let widths = [
        Constraint::Length(9),
        Constraint::Min(7),
        Constraint::Min(7),
        Constraint::Min(7),
        Constraint::Min(7),
    ];
    frame.render_widget(Table::new(rows, widths).header(header), table_area);

    let fail = target.stats.failed();
    let fail_color = if fail > 0 { Color::Red } else { Color::Green };
    let sep = Span::styled(" │ ", Style::new().fg(COLOR_DIM));
    let mut count_spans = vec![
        Span::raw(format!("sent {}", target.stats.sent())),
        sep.clone(),
        Span::raw(format!("ok {}", target.stats.succeeded())),
        sep.clone(),
        Span::styled(format!("fail {fail}"), Style::new().fg(fail_color)),
        sep.clone(),
        Span::styled(
            format!("loss {:.1}%", target.stats.loss_pct()),
            Style::new().fg(fail_color),
        ),
    ];
    // --expect 위반 누적이 있으면 표시 — 히스토리에서 스크롤되어 사라지는
    // EXPECT-FAIL 마커만으로는 타깃별 누적을 알 수 없다.
    let expect_failed = target.stats.expect_failed();
    if expect_failed > 0 {
        count_spans.push(sep);
        count_spans.push(Span::styled(
            format!("expect-fail {expect_failed}"),
            Style::new().fg(Color::Red),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(count_spans)), counts_area);
}

/// 하단: 병합 프로브 히스토리 (ping 라인 스타일, 최신이 아래) + 마지막 줄 키 도움말.
fn draw_history(frame: &mut Frame, app: &App, area: Rect) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let visible = inner_height.saturating_sub(1); // 마지막 줄은 도움말.

    let start = app.history.len().saturating_sub(visible);
    let mut lines: Vec<Line> = app
        .history
        .iter()
        .skip(start)
        .map(|r| history_line(app, r))
        .collect();
    if lines.is_empty() {
        lines.push(Line::styled(
            "waiting for first probe...",
            Style::new().fg(COLOR_DIM),
        ));
    }
    let mut help = String::from("q/esc quit │ space pause/resume │ r reset");
    if app.targets.len() > 1 {
        help.push_str(" │ tab next target");
    }
    lines.push(Line::styled(help, Style::new().fg(COLOR_DIM)));

    let title = format!("history ({} probes)", app.total_sent());
    let paragraph = Paragraph::new(lines).block(Block::bordered().title(title));
    frame.render_widget(paragraph, area);
}

/// 히스토리 한 줄: [short host](멀티 타깃) + 시각 + seq + 상태/에러 +
/// 단계별 시간 (단계 고정 색) + EXPECT-FAIL/reused 마커.
fn history_line(app: &App, result: &crate::types::ProbeResult) -> Line<'static> {
    let mut spans = Vec::new();

    // 멀티 타깃이면 short label prefix (해당 타깃 팔레트 색).
    if app.targets.len() > 1 {
        let label = app.short_label(&result.target).unwrap_or(&result.target);
        let color = app
            .target_index(&result.target)
            .map(target_color)
            .unwrap_or(COLOR_DIM);
        spans.push(Span::styled(format!("[{label}] "), Style::new().fg(color)));
    }

    let ts = result
        .timestamp
        .with_timezone(&chrono::Local)
        .format("%H:%M:%S");
    spans.push(Span::styled(format!("{ts} "), Style::new().fg(COLOR_DIM)));
    spans.push(Span::raw(format!("#{:<4} ", result.seq)));

    if let Some(err) = &result.error {
        let timeout = if err.timed_out { " (timeout)" } else { "" };
        spans.push(Span::styled(
            format!("ERROR({}) {}{timeout}", err.phase, err.message),
            Style::new().fg(Color::Red),
        ));
        return Line::from(spans);
    }

    let status = result.status().unwrap_or(0);
    // 1xx는 에러가 아니므로 무색 — text.rs(status_colored)의 CLI 출력과 일관되게.
    let status_style = match status {
        200..=299 => Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
        300..=399 => Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        100..=199 => Style::new(),
        _ => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
    };
    spans.push(Span::styled(format!("{status} "), status_style));

    let t = result.summed_timings();
    let mut push_phase = |label: &str, value: Option<f64>, color: Color| {
        if let Some(v) = value {
            spans.push(Span::styled(
                format!("{label}={v:.1} "),
                Style::new().fg(color),
            ));
        }
    };
    push_phase("dns", t.dns_ms, COLOR_DNS);
    push_phase("tcp", Some(t.tcp_ms), COLOR_TCP);
    push_phase("tls", t.tls_ms, COLOR_TLS);
    push_phase("ttfb", Some(t.ttfb_ms), COLOR_TTFB);
    push_phase("dl", Some(t.download_ms), COLOR_DOWNLOAD);
    spans.push(Span::styled(
        format!("total={:.1}ms", t.total_ms),
        Style::new().fg(COLOR_TOTAL),
    ));
    if result.hops.len() > 1 {
        spans.push(Span::styled(
            format!(" hops={}", result.hops.len()),
            Style::new().fg(COLOR_DIM),
        ));
    }
    // --expect 어설션 위반 마커 (네트워크는 성공한 경우에만 평가됨).
    if !result.expect_failures.is_empty() {
        spans.push(Span::styled(
            " EXPECT-FAIL",
            Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    // keep-alive 모드에서 최종 hop이 연결을 재사용했으면 dim 마커.
    if result.final_hop().is_some_and(|h| h.reused_conn) {
        spans.push(Span::styled(" reused", Style::new().fg(COLOR_DIM)));
    }
    Line::from(spans)
}

fn num_cell(value: f64) -> Cell<'static> {
    Cell::from(Line::from(format!("{value:.1}")).right_aligned())
}

fn dash_cell() -> Cell<'static> {
    Cell::from(Line::from("-").right_aligned()).style(Style::new().fg(COLOR_DIM))
}
