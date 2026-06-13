//! httprove — HTTP(S) 서비스 점검 도구.
//!
//! 모드 결정 (위에서부터 우선):
//! - `--cert-check`       → 인증서 일괄 점검 테이블
//! - `--listen ADDR`      → exporter 모드 (무한 프로브 + /metrics 서버)
//! - `--tui`              → TUI 대시보드 (-c 없으면 무한)
//! - `-c` 없음/`-c 1`     → 단발 상세 출력 (타깃마다 워터폴 + 인증서)
//! - `-c N` (N>1)/`-c 0`  → ping 스타일 반복 + 종료 시 요약 (0 = Ctrl-C까지)
//!
//! 멀티 타깃: 위치 인자를 여러 개 주면 모든 모드에서 타깃별로 수행한다.
//! `--save`/`--compare`: 단발/ping 모드 종료 후 베이스라인 저장/비교.
//!
//! 종료 코드: 0 = 모든 프로브 통과, 1 = 네트워크 실패/실행 오류,
//! 3 = 네트워크는 성공했지만 --expect 어설션 위반.

mod cert;
mod cert_check;
mod cli;
mod exporter;
mod output;
mod probe;
mod runner;
mod stats;
mod tui;
mod types;
mod update;

use std::collections::HashMap;
use std::io::IsTerminal;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use crate::cli::Args;
use crate::output::OutputConfig;
use crate::stats::StatsCollector;
use crate::types::ProbeResult;

/// CLI 진입점 본체. httprove/hpr 두 바이너리가 공유한다.
pub fn cli_main() -> ExitCode {
    // `httprove update [flags]` 는 프로브 인자 파서를 거치지 않고 별도 처리한다.
    // (프로브 모드는 `httprove <url>` 형태라, 첫 위치 인자가 "update"면 갈라낸다.)
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("update") {
        // "httprove update ..." → update 서브커맨드. argv[0]은 프로그램명 유지.
        let mut sub = vec![format!("{} update", program_name(&argv))];
        sub.extend(argv.iter().skip(2).cloned());
        return update::main(&sub);
    }

    let args = Args::parse();

    let color = !args.no_color && std::io::stdout().is_terminal();
    colored::control::set_override(color);

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("httprove: failed to start runtime: {e}");
            return ExitCode::from(1);
        }
    };

    match rt.block_on(run(args, color)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("httprove: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(args: Args, color: bool) -> anyhow::Result<ExitCode> {
    let interval = Duration::from_secs_f64(args.interval.max(0.0));

    // 인증서 일괄 점검 모드 (ProbeConfig 불필요 — 타깃 표기가 다름).
    if args.cert_check {
        return cert_check::run_cert_check(
            args.targets.clone(),
            Duration::from_secs_f64(args.timeout.max(0.1)),
            args.insecure,
            args.cert_warn,
            args.json,
            color,
        )
        .await;
    }

    let cfgs = args.to_probe_configs()?;
    let warn = args.parse_warn()?;
    let out_cfg = OutputConfig {
        color,
        verbose: args.verbose,
        cert_warn_days: args.cert_warn,
        warn,
        show_target: cfgs.len() > 1,
    };

    // exporter 모드: 무한 프로브 + /metrics HTTP 서버.
    if let Some(addr) = args.listen {
        return exporter::run_exporter(cfgs, addr, interval, out_cfg).await;
    }

    if args.tui {
        // TUI는 -c 미지정 시 무한 프로브. 종료 코드 계약은 CLI 모드와 동일.
        let count = match args.count {
            None | Some(0) => None,
            Some(n) => Some(n),
        };
        return tui::run_tui(cfgs, count, interval, args.cert_warn, warn).await;
    }

    // CLI 모드 (단발/핑 공용 수집 루프).
    let count = match args.count {
        None => Some(1),
        Some(0) => None,
        Some(n) => Some(n),
    };
    let single_mode = count == Some(1);
    run_cli_mode(cfgs, count, interval, single_mode, &args, out_cfg).await
}

/// 타깃별 수집 상태.
struct TargetState {
    name: String,
    stats: StatsCollector,
    last_success: Option<ProbeResult>,
}

/// 단발/핑 모드 공용 실행부: 결과 수집 → 출력 → 요약/비교/저장 → 종료 코드.
async fn run_cli_mode(
    cfgs: Vec<types::ProbeConfig>,
    count: Option<u64>,
    interval: Duration,
    single_mode: bool,
    args: &Args,
    out_cfg: OutputConfig,
) -> anyhow::Result<ExitCode> {
    let mut targets: Vec<TargetState> = cfgs
        .iter()
        .map(|c| TargetState {
            name: c.url.to_string(),
            stats: StatsCollector::new(),
            last_success: None,
        })
        .collect();
    let index: HashMap<String, usize> = targets
        .iter()
        .enumerate()
        .map(|(i, t)| (t.name.clone(), i))
        .collect();

    // --compare 베이스라인은 프로브 실행 전에 미리 로드한다 — 경로 오타/포맷 오류로
    // 측정 전체(-c가 크면 수 분)를 낭비하고 나서야 실패하지 않도록.
    let baseline = match &args.compare {
        Some(path) => Some(output::baseline::load(path)?),
        None => None,
    };

    let mut handle = runner::spawn_probe_loop(cfgs, count, interval);
    let mut printed_singles = 0usize;

    let consume =
        |result: ProbeResult, targets: &mut Vec<TargetState>, printed_singles: &mut usize| {
            if let Some(&i) = index.get(&result.target) {
                targets[i].stats.record(&result);
                if result.is_success() {
                    targets[i].last_success = Some(result.clone());
                }
            }
            if args.json {
                println!("{}", output::json::probe_json(&result));
            } else if args.prom {
                // --prom: stdout은 Prometheus textfile-collector 스냅샷 전용.
                // seq=... 사람용 라인이 섞이면 node_exporter가 .prom 파일 전체를
                // 거부하므로 프로브별 출력은 내지 않는다.
            } else if single_mode {
                // 멀티 타깃 단발: 블록 사이 빈 줄.
                if *printed_singles > 0 {
                    println!();
                }
                output::text::print_single(&result, &out_cfg);
                *printed_singles += 1;
            } else {
                output::text::print_ping_line(&result, &out_cfg);
            }
        };

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                handle.cancel.cancel();
                // 진행 중이던 결과가 있으면 마저 수신.
                while let Some(result) = handle.rx.recv().await {
                    consume(result, &mut targets, &mut printed_singles);
                }
                break;
            }
            recv = handle.rx.recv() => {
                match recv {
                    Some(result) => consume(result, &mut targets, &mut printed_singles),
                    None => break, // 모든 타깃 count 도달.
                }
            }
        }
    }

    // --- 요약 출력 ---------------------------------------------------------
    if args.json {
        if !single_mode {
            for t in &targets {
                println!("{}", output::json::summary_json(&t.name, &t.stats));
            }
        }
    } else if args.prom {
        let metrics: Vec<output::prom::TargetMetrics> = targets
            .iter()
            .map(|t| output::prom::TargetMetrics {
                target: &t.name,
                stats: &t.stats,
                last_success: t.last_success.as_ref(),
            })
            .collect();
        print!("{}", output::prom::render(&metrics));
    } else if !single_mode {
        for (i, t) in targets.iter().enumerate() {
            if i > 0 {
                println!();
            }
            let last_cert = t.last_success.as_ref().and_then(|r| r.leaf_cert());
            output::text::print_summary(&t.name, &t.stats, last_cert, &out_cfg);
        }
    }

    // --- 베이스라인 비교/저장 ----------------------------------------------
    if args.compare.is_some() || args.save.is_some() {
        let rows: Vec<(String, &StatsCollector, Option<i64>)> = targets
            .iter()
            .map(|t| {
                let cert_days = t
                    .last_success
                    .as_ref()
                    .and_then(|r| r.leaf_cert())
                    .map(|c| c.days_remaining);
                (t.name.clone(), &t.stats, cert_days)
            })
            .collect();
        let current = output::baseline::build(&rows);

        if let (Some(path), Some(base)) = (&args.compare, &baseline) {
            println!();
            output::baseline::print_comparison(path, base, &current, out_cfg.color);
        }
        if let Some(path) = &args.save {
            output::baseline::save(path, &current)?;
            eprintln!("httprove: baseline saved to {path}");
        }
    }

    // --- 종료 코드 ----------------------------------------------------------
    let net_failed = targets.iter().any(|t| t.stats.failed() > 0);
    let expect_failed = targets.iter().any(|t| t.stats.expect_failed() > 0);
    Ok(if net_failed {
        ExitCode::from(1)
    } else if expect_failed {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    })
}

/// argv[0]에서 프로그램명(httprove/hpr)만 추출한다 (update 서브커맨드 usage 표시용).
fn program_name(argv: &[String]) -> String {
    argv.first()
        .and_then(|p| std::path::Path::new(p).file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("httprove")
        .to_string()
}
