//! `--listen` exporter 모드: 지속 프로브 + /metrics HTTP 서버.
//!
//! ## 동작
//! - runner::spawn_probe_loop(cfgs, None, interval)로 무한 프로브를 돌리면서
//!   결과를 수신해 (1) 타깃별 StatsCollector/마지막 성공 결과를 갱신하고
//!   (2) ping 라인을 stdout에 출력한다 (out_cfg 사용, 멀티 타깃이면 타깃 표시).
//! - 동시에 listen 주소에서 미니 HTTP/1.1 서버를 돌린다 (의존성 추가 없이 직접 구현):
//!   - 요청을 8KB까지 읽고 첫 줄만 파싱 ("GET <path> HTTP/1.x").
//!   - GET /metrics → 200, Content-Type: text/plain; version=0.0.4,
//!     바디는 output::prom::render(현재 상태 스냅샷).
//!   - GET / → 200 text/html, /metrics 링크가 있는 한 줄 안내 페이지.
//!   - 그 외 → 404. 모든 응답에 Content-Length + Connection: close, 응답 후 종료.
//!   - 커넥션 처리 태스크는 5초 타임아웃으로 보호.
//! - 상태 공유: Arc<Mutex<...>> (타깃 순서 보존 — Vec<(String, StatsCollector,
//!   Option<ProbeResult>)> 권장, 타깃 수는 적으므로 선형 탐색이면 충분).
//! - Ctrl-C → 프로브 cancel, 서버 종료, ExitCode::SUCCESS 반환.
//!   바인드 실패는 anyhow 에러로 즉시 반환.
//! - 시작 시 stderr에 "listening on http://<addr>/metrics" 한 줄 안내.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::output::prom::{self, TargetMetrics};
use crate::output::{self, OutputConfig};
use crate::runner;
use crate::stats::StatsCollector;
use crate::types::{ProbeConfig, ProbeResult, VerdictState};

/// 요청 헤드 최대 수신 크기.
const MAX_REQUEST_HEAD: usize = 8 * 1024;

/// 커넥션 1개 처리(읽기+응답) 전체 타임아웃.
const CONN_TIMEOUT: Duration = Duration::from_secs(5);

/// 동시 처리 커넥션 상한. 초과분은 응답 없이 즉시 닫는다
/// (소켓/태스크 무한 증식 → FD 고갈 방지. /metrics 스크레이프에는 충분한 수치).
const MAX_CONNECTIONS: usize = 64;

/// accept 실패(EMFILE 등) 후 재시도 전 대기. 즉시 재시도가 반복되면 busy-spin으로
/// 코어를 태우고 같은 런타임의 프로브/업데이트 태스크를 굶기게 된다.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// 타깃별 공유 상태: (타깃 URL, 누적 통계, 마지막 성공 결과, 최신 결과의 health 판정).
/// 마지막 필드는 B12/B13 메트릭용 — 매 결과(성공/실패)마다 갱신한다. 타깃 순서 보존.
type SharedState = Arc<
    Mutex<
        Vec<(
            String,
            StatsCollector,
            Option<ProbeResult>,
            Option<VerdictState>,
        )>,
    >,
>;

/// exporter 모드 실행. Ctrl-C까지 블로킹.
pub async fn run_exporter(
    cfgs: Vec<ProbeConfig>,
    listen: SocketAddr,
    interval: Duration,
    out_cfg: OutputConfig,
) -> anyhow::Result<ExitCode> {
    // SLO는 설정값(Copy) — out_cfg가 update 태스크로 move되기 전에 추출해 accept 루프가 쓴다.
    let slo = out_cfg.slo;
    // 타깃 순서대로 상태 슬롯 초기화 (Apdex 임계 주입).
    let state: SharedState = Arc::new(Mutex::new(
        cfgs.iter()
            .map(|c| {
                (
                    c.url.to_string(),
                    StatsCollector::with_apdex_threshold(out_cfg.apdex_threshold),
                    None,
                    None,
                )
            })
            .collect(),
    ));

    // 바인드 실패는 즉시 에러 반환.
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind {listen}"))?;
    // 실제 바인드된 주소 출력 (포트 0 지정 시 유용). 조회 실패 시 요청 주소로 대체.
    let local = listener.local_addr().unwrap_or(listen);
    eprintln!("listening on http://{local}/metrics");

    // 무한 프로브 루프 시작 (count = None).
    let handle = runner::spawn_probe_loop(cfgs, None, interval);
    let cancel = handle.cancel.clone();
    let mut rx = handle.rx;

    // 업데이트 태스크: 결과 수신 → 상태 갱신 + ping 라인 출력.
    // rx가 닫히면(모든 프로브 태스크 종료) 자연 종료된다.
    let update_state = Arc::clone(&state);
    let update_task = tokio::spawn(async move {
        // B12/B13 판정 컨텍스트(임계/cert). 매 결과를 최신 판정으로 갱신하는 데 쓴다.
        let vctx = crate::verdict::VerdictContext {
            warn: out_cfg.warn,
            cert_warn_days: out_cfg.cert_warn_days,
            baseline_total_ms: None,
        };
        while let Some(result) = rx.recv().await {
            {
                // Mutex poisoning은 무시하고 내부 데이터를 계속 사용한다.
                let mut slots = update_state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(slot) = slots
                    .iter_mut()
                    .find(|(name, _, _, _)| *name == result.target)
                {
                    slot.1.record(&result);
                    // 최신 결과(성공/실패) 기준 판정 — 실패면 Down으로 반영된다.
                    slot.3 = Some(crate::verdict::assess(&result, &vctx).state);
                    if result.is_success() {
                        slot.2 = Some(result.clone());
                    }
                }
            } // /metrics 응답을 막지 않도록 출력 전에 락 해제.
            output::text::print_ping_line(&result, &out_cfg);
        }
    });

    // accept 루프: Ctrl-C까지. ctrl_c future는 시그널 유실이 없도록 1회만 만든다.
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            _ = &mut ctrl_c => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        match Arc::clone(&conn_limit).try_acquire_owned() {
                            Ok(permit) => {
                                let state = Arc::clone(&state);
                                tokio::spawn(async move {
                                    // permit은 태스크 종료까지 보유 (동시 커넥션 상한).
                                    let _permit = permit;
                                    // 느린/멈춘 클라이언트로부터 태스크 보호.
                                    let _ = tokio::time::timeout(
                                        CONN_TIMEOUT,
                                        handle_connection(stream, state, slo),
                                    )
                                    .await;
                                });
                            }
                            // 상한 초과: 응답 없이 즉시 닫는다 (stream drop).
                            Err(_) => drop(stream),
                        }
                    }
                    // 일시적 accept 오류(파일 디스크립터 고갈 등)는 기록 후 잠시 쉬고 계속.
                    Err(e) => {
                        eprintln!("httprove: accept error: {e}");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    }
                }
            }
        }
    }

    // Ctrl-C: 프로브 중단 → rx가 닫히며 업데이트 태스크도 잔여 결과 처리 후 종료.
    cancel.cancel();
    let _ = update_task.await;
    Ok(ExitCode::SUCCESS)
}

/// 커넥션 1개 처리: 요청 라인 파싱 → 라우팅 → 응답 → 종료.
async fn handle_connection(mut stream: TcpStream, state: SharedState, slo: Option<f64>) {
    let Some(request_line) = read_request_line(&mut stream).await else {
        // 요청 라인을 받지 못함 (EOF/읽기 오류/8KB 초과) — 응답 없이 닫는다.
        return;
    };

    match route(&request_line) {
        Route::Metrics => {
            // 락 구간 최소화: 스냅샷 렌더링까지만 잡고 즉시 해제.
            let body = {
                let slots = state.lock().unwrap_or_else(|e| e.into_inner());
                let metrics: Vec<TargetMetrics<'_>> = slots
                    .iter()
                    .map(|(name, stats, last, vstate)| TargetMetrics {
                        target: name,
                        stats,
                        last_success: last.as_ref(),
                        verdict_state: *vstate,
                        slo,
                    })
                    .collect();
                prom::render(&metrics)
            };
            write_response(&mut stream, "200 OK", "text/plain; version=0.0.4", &body).await;
        }
        Route::Index => {
            let body =
                "<html><body>httprove exporter — <a href=\"/metrics\">/metrics</a></body></html>\n";
            write_response(&mut stream, "200 OK", "text/html; charset=utf-8", body).await;
        }
        Route::NotFound => {
            write_response(
                &mut stream,
                "404 Not Found",
                "text/plain; charset=utf-8",
                "not found\n",
            )
            .await;
        }
    }
}

/// 라우팅 결과.
enum Route {
    Metrics,
    Index,
    NotFound,
}

/// 요청 라인("GET <path> HTTP/1.x")을 라우팅한다. 그 외는 전부 404.
fn route(request_line: &str) -> Route {
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(raw_path)) = (parts.next(), parts.next()) else {
        return Route::NotFound;
    };
    if method != "GET" {
        return Route::NotFound;
    }
    // 쿼리스트링은 무시한다 (예: /metrics?foo=1).
    let path = raw_path.split('?').next().unwrap_or(raw_path);
    match path {
        "/metrics" => Route::Metrics,
        "/" => Route::Index,
        _ => Route::NotFound,
    }
}

/// 요청 첫 줄을 읽는다. 라우팅에는 첫 줄만 필요하지만, 헤더 끝(빈 줄)까지
/// 읽어 커널 수신 버퍼를 비워 둔다 — 미수신 바이트가 남은 채로 응답 후 닫으면
/// TCP RST로 응답 자체가 유실될 수 있다 (GET 요청이므로 바디는 없다).
/// 8KB 상한/EOF에 도달하면 그때까지 받은 데이터의 첫 줄로 진행한다.
async fn read_request_line(stream: &mut TcpStream) -> Option<String> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        // 헤더 종료(빈 줄)까지 수신 완료 — 첫 줄 반환.
        if headers_complete(&buf) {
            return first_line(&buf);
        }
        if buf.len() >= MAX_REQUEST_HEAD {
            // 8KB 안에 헤더가 안 끝남 — 요청 라인이라도 있으면 그걸로 응답한다.
            return first_line(&buf);
        }
        match stream.read(&mut chunk).await {
            Ok(0) => return first_line(&buf), // EOF — 받은 만큼으로 진행.
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    }
}

/// 요청 헤드가 빈 줄("\r\n\r\n" 또는 "\n\n")로 끝났는지.
fn headers_complete(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.windows(2).any(|w| w == b"\n\n")
}

/// 수신 버퍼의 첫 줄(개행 전까지, CR 제거). 개행이 없으면 None.
fn first_line(buf: &[u8]) -> Option<String> {
    let pos = buf.iter().position(|&b| b == b'\n')?;
    let line = String::from_utf8_lossy(&buf[..pos]);
    Some(line.trim_end_matches('\r').to_string())
}

/// HTTP/1.1 응답을 쓰고 연결을 종료한다. 쓰기 실패는 무시 (클라이언트가 끊은 경우 등).
async fn write_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
}
