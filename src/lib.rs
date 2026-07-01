//! httprove — HTTP(S) 서비스 점검 도구.
//!
//! 모드 결정 (위에서부터 우선):
//! - `serve [ADDR]`       → 들어오는 요청 인스펙터/에코 서버 (서브커맨드)
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

mod blackbox;
mod cache_audit;
mod cert;
mod cert_check;
mod chain;
mod cli;
mod diff;
mod dns;
mod exporter;
mod fanout;
mod hash;
mod ipinfo;
mod otlp;
mod output;
mod probe;
mod record;
mod runner;
mod serve;
mod stats;
mod tls_grade;
mod trace;
mod tui;
mod types;
mod update;
mod verdict;
mod watch;

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

    // `httprove serve [ADDR] ...` → 들어오는 요청 인스펙터/에코 서버.
    // update와 동일하게 합성 argv("{prog} serve" + 나머지)로 자체 clap 파서에 넘긴다.
    if argv.get(1).map(String::as_str) == Some("serve") {
        let mut sub = vec![format!("{} serve", program_name(&argv))];
        sub.extend(argv.iter().skip(2).cloned());
        return serve::main(&sub);
    }

    // 조사용 서브커맨드 — 프로브 인자 파서를 거치지 않는 별도 진입점.
    // (update와 동일하게 첫 위치 인자로 갈라낸다.)
    if let Some(sub) = argv.get(1).map(String::as_str)
        && matches!(sub, "diff" | "trace" | "replay")
    {
        return run_subcommand(sub, &argv);
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

/// diff/trace/replay 서브커맨드 디스패치. argv는 프로그램명부터 시작하는 전체 인자.
/// 이 경로는 프로브 인자 파서(clap Args)를 거치지 않으므로 색상은 --no-color + tty로 판단한다.
fn run_subcommand(sub: &str, argv: &[String]) -> ExitCode {
    let no_color = argv.iter().any(|a| a == "--no-color");
    let color = !no_color && std::io::stdout().is_terminal();
    colored::control::set_override(color);
    // 서브커맨드 위치 인자(프로그램명·서브커맨드명·--no-color 제외).
    let positionals: Vec<&str> = argv
        .iter()
        .skip(2)
        .filter(|a| a.as_str() != "--no-color")
        .map(String::as_str)
        .collect();

    match sub {
        // "httprove diff a.json b.json" → 두 프로브 JSON의 필드 단위 diff.
        "diff" => {
            let (Some(a), Some(b)) = (positionals.first(), positionals.get(1)) else {
                eprintln!("usage: httprove diff <a.json> <b.json>");
                return ExitCode::from(1);
            };
            diff::run_diff(a, b, color)
        }
        // "httprove replay <session.json>" → 기록된 세션을 다시 렌더링.
        "replay" => {
            let Some(path) = positionals.first() else {
                eprintln!("usage: httprove replay <session.json>");
                return ExitCode::from(1);
            };
            record::run_replay(path, color)
        }
        // "httprove trace <url>" → 시스템 traceroute + TLS 종단 hop 주석.
        "trace" => {
            let Some(raw) = positionals.first() else {
                eprintln!("usage: httprove trace <url>");
                return ExitCode::from(1);
            };
            let cfg = match minimal_probe_config(raw) {
                Ok(cfg) => cfg,
                Err(e) => {
                    eprintln!("httprove: {e:#}");
                    return ExitCode::from(1);
                }
            };
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("httprove: failed to start runtime: {e}");
                    return ExitCode::from(1);
                }
            };
            match rt.block_on(trace::run_trace(&cfg, color)) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("httprove: {e:#}");
                    ExitCode::from(1)
                }
            }
        }
        _ => unreachable!("run_subcommand called with non-subcommand"),
    }
}

/// 서브커맨드(trace 등)용 최소 ProbeConfig 빌더. URL만 정규화하고 나머지는 기본값.
/// 스킴이 없으면 https://를 붙인다 (Args::to_probe_configs와 동일 규칙).
fn minimal_probe_config(raw: &str) -> anyhow::Result<types::ProbeConfig> {
    use anyhow::{Context, bail};

    let raw = raw.trim();
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let url = url::Url::parse(&with_scheme).with_context(|| format!("invalid URL: {raw}"))?;
    match url.scheme() {
        "http" | "https" => {}
        other => bail!("unsupported scheme: {other} (only http/https)"),
    }
    if url.host_str().is_none() {
        bail!("URL has no host: {raw}");
    }
    Ok(types::ProbeConfig {
        url,
        method: "GET".to_string(),
        headers: Vec::new(),
        body: None,
        timeout: Duration::from_secs(10),
        resolve: None,
        dns_servers: Vec::new(),
        ecs: None,
        ip_family: types::IpFamily::Auto,
        insecure: false,
        http_version: types::HttpVersionPref::Auto,
        max_redirects: 0,
        keep_alive: false,
        expect: types::Expectations::default(),
        trace_id: None,
    })
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

    let mut cfgs = if let Some(bbpath) = &args.blackbox_config {
        // blackbox_exporter modules YAML(http prober)을 ProbeConfig로 변환한다.
        let bb = blackbox::BlackboxConfig::load(bbpath)?;
        let module_name = args.module.as_deref().unwrap_or("http_2xx");
        let module = bb.module(module_name).ok_or_else(|| {
            anyhow::anyhow!("blackbox module '{module_name}' not found in {bbpath}")
        })?;
        anyhow::ensure!(
            args.timeout > 0.0 && args.timeout.is_finite(),
            "--timeout must be a positive finite number"
        );
        let timeout = std::time::Duration::from_secs_f64(args.timeout);
        args.targets
            .iter()
            .map(|t| blackbox::to_probe_config(module, t, timeout))
            .collect::<anyhow::Result<Vec<_>>>()?
    } else {
        args.to_probe_configs()?
    };

    // ㊲ --traceparent: 각 요청에 W3C traceparent 헤더를 주입한다.
    // 설정당 trace-id를 한 번 만들어 (1) 헤더와 (2) cfg.trace_id에 함께 저장한다 —
    // 그래야 나중에 OTLP export가 같은 trace-id를 재사용해 백엔드에서 상관된다.
    if args.traceparent {
        for cfg in &mut cfgs {
            let trace_hex = otlp::new_trace_id_hex();
            cfg.headers.push((
                "traceparent".to_string(),
                otlp::make_traceparent_from(&trace_hex),
            ));
            cfg.trace_id = Some(trace_hex);
        }
    }

    // === 조사(investigation) 모드 — 단발성, 자체 종료 코드 ===================
    // 첫 타깃을 대표 설정으로 사용한다 (이 모드들은 단일 호스트 진단용).
    // 정상 단발/핑 흐름보다 먼저 갈라낸다.
    if args.fanout || args.all_families || args.via.is_some() {
        let cfg = cfgs
            .first()
            .ok_or_else(|| anyhow::anyhow!("no target for investigation mode"))?;
        if args.fanout {
            return fanout::run_fanout(cfg, color).await;
        }
        if args.all_families {
            return fanout::run_all_families(cfg, color).await;
        }
        // --via: CSV 리졸버로 질의 후 POP 비교.
        let resolvers = args.parse_via_resolvers()?;
        return dns::run_via_resolvers(cfg, &resolvers, args.ecs.as_deref(), color).await;
    }

    let warn = args.parse_warn()?;
    let out_cfg = OutputConfig {
        color,
        verbose: args.verbose,
        cert_warn_days: args.cert_warn,
        warn,
        show_target: cfgs.len() > 1,
        slo: args.slo,
        apdex_threshold: args.apdex_threshold,
    };

    // exporter 모드: 무한 프로브 + /metrics HTTP 서버.
    if let Some(addr) = args.listen {
        // blackbox config + --listen → /probe?target=&module= 엔드포인트 모드(target은 쿼리로).
        if let Some(bbpath) = &args.blackbox_config {
            let bb = blackbox::BlackboxConfig::load(bbpath)?;
            let module = args
                .module
                .clone()
                .unwrap_or_else(|| "http_2xx".to_string());
            let timeout = std::time::Duration::from_secs_f64(args.timeout.max(0.001));
            return exporter::run_blackbox_exporter(bb, addr, module, timeout).await;
        }
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
    /// 최신 결과(error 포함)의 health 판정. B12/B13 메트릭용 — last_success가 아니라
    /// 매 결과마다 갱신해 실패를 Down으로 반영한다. 결과 수신 전이면 None.
    latest_state: Option<types::VerdictState>,
    /// C3 watch/alert: --on-breach 발화 추적 상태(연속 breach/쿨다운/복구).
    breach: watch::BreachTracker,
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
            stats: StatsCollector::with_apdex_threshold(out_cfg.apdex_threshold),
            last_success: None,
            latest_state: None,
            breach: watch::BreachTracker::default(),
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

    // ㉝ 캡처 트랩 모드: 첫 실패가 관측될 때까지 무한 프로브 → 세션 저장 + 실패 결과 출력.
    // 정상 수집 루프와 흐름이 달라 별도 함수로 처리하고 여기서 일찍 반환한다.
    if args.trap {
        return run_trap_mode(cfgs, interval, &out_cfg, args).await;
    }

    // ㉟㉞ 세션 record/HTML report는 실행 종료 후 누적 결과 전체를 한 번에 직렬화하므로,
    // -c 0(무한)과 함께 쓰면 captured가 무한히 자라고 산출물도 영원히 안 나온다 — 거부한다.
    // (OTLP는 아래에서 프로브별로 스트리밍하므로 무한 실행과 함께 써도 누수가 없다.)
    if count.is_none() && (args.report.is_some() || args.record.is_some()) {
        anyhow::bail!(
            "--report/--record need a bounded run; combine with -c N (not -c 0 / run-until-Ctrl-C)"
        );
    }

    // ㊲ OTLP는 프로브별로 즉시 내보내므로(스트리밍) captured에 쌓지 않는다.
    // record/report만 종료 후 일괄 직렬화를 위해 누적한다.
    let capture_results = args.report.is_some() || args.record.is_some();
    let mut captured: Vec<ProbeResult> = Vec::new();

    // ㊲ OTLP export가 --traceparent와 같은 trace-id를 쓰도록, 타깃 URL → trace-id 맵을
    // cfgs가 runner로 이동되기 전에 만들어 둔다 (export는 ProbeResult.target으로 조회).
    let trace_id_by_target: HashMap<String, String> = cfgs
        .iter()
        .filter_map(|c| c.trace_id.as_ref().map(|t| (c.url.to_string(), t.clone())))
        .collect();
    // 죽은 collector가 프로브마다 15s 커넥트 타임아웃을 누적시키지 않도록, 첫 도달 실패
    // 이후에는 남은 export를 차단한다 (circuit-break). true면 export 중단.
    let mut otlp_circuit_open = false;

    // ①② verdict/explain 출력에 쓸 컨텍스트. baseline_total은 --compare 베이스라인이
    // 있으면 그 total을 기준선으로 쓸 수 있으나(여기서는 None), 임계값/cert는 항상 적용.
    let vctx = verdict::VerdictContext {
        warn: out_cfg.warn,
        cert_warn_days: out_cfg.cert_warn_days,
        baseline_total_ms: None,
    };
    // C3 watch/alert: --on-breach 재발화 억제 쿨다운.
    let watch_cooldown = Duration::from_secs_f64(args.cooldown.max(0.0));

    let mut handle = runner::spawn_probe_loop(cfgs, count, interval);
    let mut printed_singles = 0usize;

    let consume = |result: ProbeResult,
                   targets: &mut Vec<TargetState>,
                   printed_singles: &mut usize,
                   captured: &mut Vec<ProbeResult>| {
        if let Some(&i) = index.get(&result.target) {
            targets[i].stats.record(&result);
            // 최신 결과(성공/실패) 기준 판정 — B12/B13 메트릭 + C3 watch가 공용으로 쓴다.
            let v = verdict::assess(&result, &vctx);
            targets[i].latest_state = Some(v.state);
            // C3 watch/alert: ping 모드 breach/recover webhook 발화 (fire-and-forget).
            if let Some(url) = &args.on_breach {
                let breached = v.state != types::VerdictState::Pass;
                let event = targets[i].breach.evaluate(
                    breached,
                    args.breach_after,
                    watch_cooldown,
                    args.on_recover,
                    std::time::Instant::now(),
                );
                match event {
                    watch::Fire::Breach => watch::fire(
                        url.clone(),
                        watch::payload("breach", &result, v.state, &v.headline),
                    ),
                    watch::Fire::Recover => watch::fire(
                        url.clone(),
                        watch::payload("recover", &result, v.state, &v.headline),
                    ),
                    watch::Fire::None => {}
                }
            }
            if result.is_success() {
                targets[i].last_success = Some(result.clone());
            }
        }
        if capture_results {
            captured.push(result.clone());
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
            // ① verdict 한 줄 / ② explain 문장 (단발 출력 직후).
            if args.verdict {
                let v = verdict::assess(&result, &vctx);
                println!("verdict:  {} — {}", v.state.label(), v.headline);
            }
            if args.explain {
                println!("{}", verdict::explain(&result));
            }
            // TLS 연결 보안 스코어카드 (협상된 구성 + HSTS + 체인 종합 A~F).
            if args.tls_grade
                && let Some(hop) = result.final_hop()
                && let Some(tls) = &hop.tls
            {
                let analysis = crate::chain::analyze(&hop.cert_chain);
                let g = tls_grade::grade(tls, &hop.response_headers, &analysis);
                println!("tls-grade: {} ({}/100) — {}", g.letter, g.score, g.summary);
                for d in &g.deductions {
                    println!("           - {d}");
                }
            }
            // CDN/캐시 효율 진단 (응답 헤더 시그널 기반).
            if args.cache_audit
                && let Some(hop) = result.final_hop()
            {
                let a = cache_audit::audit(&hop.response_headers);
                println!("cache:     {}", a.summary);
                if let Some(edge) = &a.edge {
                    println!("           edge: {edge}");
                }
                for issue in &a.issues {
                    println!("           - {issue}");
                }
            }
            // ㊲ --otlp: 서버가 보낸 Server-Timing(있으면)을 파싱해 표시한다.
            // (트레이스는 export_otlp가 별도로 전송하고, 여기서는 서버측 분해 시간을 노출.)
            if args.otlp.is_some()
                && let Some(hop) = result.final_hop()
            {
                let timings = otlp::parse_server_timing(&hop.response_headers);
                if !timings.is_empty() {
                    let parts: Vec<String> = timings
                        .iter()
                        .map(|(name, dur)| match dur {
                            Some(ms) => format!("{name}={ms:.1}ms"),
                            None => name.clone(),
                        })
                        .collect();
                    println!("server-timing: {}", parts.join("  "));
                }
            }
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
                    stream_otlp(&result, args, &trace_id_by_target, &mut otlp_circuit_open).await;
                    consume(result, &mut targets, &mut printed_singles, &mut captured);
                }
                break;
            }
            recv = handle.rx.recv() => {
                match recv {
                    Some(result) => {
                        // ㊲ 프로브별 OTLP 스트리밍 (캡처 누적 없이 즉시 전송).
                        stream_otlp(&result, args, &trace_id_by_target, &mut otlp_circuit_open).await;
                        consume(result, &mut targets, &mut printed_singles, &mut captured);
                    }
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
                verdict_state: t.latest_state,
                slo: out_cfg.slo,
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

    // IP 인텔리전스 (--asn): 각 타깃의 연결 IP를 Team Cymru DNS로 조회한다(single/ping 공용).
    // 기계 출력(json/prom)과는 섞지 않는다.
    if args.asn && !args.json && !args.prom {
        let resolver: std::net::IpAddr = std::net::Ipv4Addr::new(1, 1, 1, 1).into();
        for t in &targets {
            let Some(last) = &t.last_success else {
                continue;
            };
            let Some(hop) = last.final_hop() else {
                continue;
            };
            let info = ipinfo::lookup(hop.ip, resolver).await;
            let server = hop
                .response_headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                .map(|(_, v)| v.as_str());
            let kind = ipinfo::classify(&info, server);
            let asn = info
                .asn
                .map(|a| format!("AS{a}"))
                .unwrap_or_else(|| "AS?".to_string());
            println!(
                "ip-info:  {} {} {} ({})  PTR: {}  [{}]",
                hop.ip,
                asn,
                info.org.as_deref().unwrap_or("?"),
                info.country.as_deref().unwrap_or("?"),
                info.ptr.as_deref().unwrap_or("-"),
                kind.label(),
            );
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

    // --- ①② verdict/explain 요약 라인 (핑/멀티 요약 모드) -------------------
    // 마지막 성공 결과를 기준으로 타깃별 한 줄 판정/설명을 덧붙인다.
    if (args.verdict || args.explain) && !single_mode && !args.json && !args.prom {
        for t in &targets {
            if let Some(last) = &t.last_success {
                if args.verdict {
                    let v = verdict::assess(last, &vctx);
                    println!("[{}] verdict: {} — {}", t.name, v.state.label(), v.headline);
                }
                if args.explain {
                    println!("[{}] {}", t.name, verdict::explain(last));
                }
            }
        }
    }

    // --- ⑦⑧ fingerprint 변경 탐지 (--since-good / --annotate-deploy) --------
    // 마지막 성공 결과의 지문을 저장된 기준 프로브와 비교한다. on-change면 종료 코드에 반영.
    // 두 플래그는 같은 지문 delta를 쓰되 출력 의미가 다르다:
    //   --since-good     → 마지막으로 정상이던 상태 대비 "무엇이 바뀌었나" 원시 diff.
    //   --annotate-deploy→ 배포 검증용 주석: 지문이 바뀌면 "deploy 반영됨", 아니면 "변화 없음"을
    //                      verdict/출력에 덧붙인다 (CI 배포 후 서비스 신원 확인).
    let mut fingerprint_changed = false;
    if let Some(path) = args
        .since_good
        .as_deref()
        .or(args.annotate_deploy.as_deref())
    {
        let deploy_mode = args.annotate_deploy.is_some() && args.since_good.is_none();

        // 이번 실행에서 기준으로 쓸/저장할 마지막 성공 결과 (첫 타깃 우선).
        let current_good = targets.iter().find_map(|t| t.last_success.as_ref());

        // 기준 파일이 없으면(부트스트랩) diff 대신 현재 정상 상태를 기록해, 다음 실행이
        // 비교 기준을 갖도록 한다. 이렇게 해야 문서의 "두 번 실행 → 두 번째가 첫 번째와 diff"
        // 워크플로가 처음부터 동작한다 (이전엔 파일 부재로 매번 에러 종료했음).
        if !std::path::Path::new(path).exists() {
            match current_good {
                Some(good) => {
                    persist_since_good(path, good)?;
                    println!(
                        "{}: recorded current state as last-known-good baseline ({} field(s) captured)",
                        path,
                        diff::fingerprint(good).headers.len()
                    );
                }
                None => {
                    eprintln!(
                        "httprove: no successful probe to seed last-known-good baseline {path}"
                    );
                }
            }
        } else {
            let prev = diff::load_probe(path)?;
            // 기준 프로브가 실패/빈 결과면(final_hop 없음) 비교 기준으로 쓸 수 없다.
            // 모든 필드를 가짜 "변경"으로 토해내 --on-change를 영구히 트립시키므로 건너뛴다.
            if prev.final_hop().is_none() {
                eprintln!(
                    "httprove: since-good baseline {path} has no successful hop; cannot compare"
                );
            } else {
                let prev_fp = diff::fingerprint(&prev);
                for t in &targets {
                    if let Some(last) = &t.last_success {
                        let cur_fp = diff::fingerprint(last);
                        let delta = diff::diff_fingerprints(&prev_fp, &cur_fp);
                        if !delta.is_empty() {
                            fingerprint_changed = true;
                            if deploy_mode {
                                // 배포 주석: 변경 사실을 verdict처럼 한 줄로 요약 + 상세 delta.
                                println!(
                                    "[{}] deploy: service fingerprint CHANGED vs {path} ({} field(s))",
                                    t.name,
                                    delta.len()
                                );
                            } else {
                                println!("[{}] fingerprint changed vs {path}:", t.name);
                            }
                            for line in &delta {
                                println!("  {line}");
                            }
                        } else if deploy_mode {
                            println!(
                                "[{}] deploy: service fingerprint unchanged vs {path}",
                                t.name
                            );
                        }
                    }
                }
                if !fingerprint_changed && !deploy_mode {
                    println!("fingerprint unchanged vs {path}");
                }

                // --since-good은 "마지막으로 정상이던 상태"를 추적하므로, 비교 후 현재 정상
                // 상태로 기준을 갱신한다 (annotate-deploy는 고정 배포 스냅샷이라 갱신하지 않음).
                if !deploy_mode && let Some(good) = current_good {
                    persist_since_good(path, good)?;
                }
            }
        }
    }

    // --- ㉑ 체인 완결성 + AIA 복구 점검 (--check-chain) ---------------------
    // 마지막 성공 결과의 leaf 체인을 분석한다. caIssuers URL은 leaf CertInfo에 보존돼
    // 있어 AIA 네트워크 복구를 best-effort로 조회한다. 타임아웃은 프로브 예산 재사용.
    // (--check-chain은 cli에서 insecure를 강제하므로, 검증 실패 호스트도 체인을 수집해
    //  여기서 last_success로 잡힌다.)
    if args.check_chain {
        let aia_timeout = Duration::from_secs_f64(args.timeout.max(0.1));
        for t in &targets {
            let Some(last) = &t.last_success else {
                continue;
            };
            let Some(hop) = last.hops.iter().rev().find(|h| !h.cert_chain.is_empty()) else {
                continue;
            };
            let analysis = chain::check_aia(&hop.cert_chain, aia_timeout).await;
            println!(
                "[{}] chain: {} (weakest {} @ {}d){}",
                t.name,
                if analysis.incomplete {
                    "incomplete"
                } else {
                    "complete"
                },
                analysis.weakest_subject,
                analysis.weakest_days,
                match analysis.aia_repairable {
                    Some(true) => " — AIA repairable",
                    Some(false) => " — AIA not repairable",
                    None => "",
                }
            );
            for issue in &analysis.issues {
                println!("  ! {issue}");
            }
        }
    }

    // ㊲ OTLP export는 위 수집 루프에서 프로브별로 스트리밍했다 (stream_otlp).

    // --- ㉞ 세션 기록 (--record) --------------------------------------------
    if let Some(path) = &args.record {
        record::save_session(&captured, path)?;
        eprintln!("httprove: session recorded to {path}");
    }

    // --- ㉟ HTML 리포트 (--report) ------------------------------------------
    if let Some(path) = &args.report {
        let verdicts: Vec<types::Verdict> =
            captured.iter().map(|r| verdict::assess(r, &vctx)).collect();
        output::html::write_report(&captured, &verdicts, path)?;
        eprintln!("httprove: HTML report written to {path}");
    }

    // --- 종료 코드 ----------------------------------------------------------
    let net_failed = targets.iter().any(|t| t.stats.failed() > 0);
    let expect_failed = targets.iter().any(|t| t.stats.expect_failed() > 0);
    Ok(if net_failed {
        ExitCode::from(1)
    } else if expect_failed {
        ExitCode::from(3)
    } else if args.on_change && fingerprint_changed {
        // --on-change: 지문이 바뀌면 비-0으로 알린다 (CI 배포 검증용).
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// ㉝ 캡처 트랩: 첫 실패가 관측될 때까지 반복 프로브하고, 그때까지의 모든 결과를
/// 세션 파일로 저장한 뒤 실패한 프로브를 상세 출력한다.
///
/// 저장 경로는 --record가 있으면 그 값을, 없으면 "httprove-trap.json"을 쓴다.
/// 종료 코드: 실패를 잡아 저장했으면 1 (트랩이 걸린 것이 정상 동작), Ctrl-C로 중단 시 SUCCESS.
async fn run_trap_mode(
    cfgs: Vec<types::ProbeConfig>,
    interval: Duration,
    out_cfg: &OutputConfig,
    args: &Args,
) -> anyhow::Result<ExitCode> {
    let save_path = args
        .record
        .clone()
        .unwrap_or_else(|| "httprove-trap.json".to_string());

    // ㊲ OTLP export용 타깃→trace-id 맵 (cfgs 이동 전에 만든다).
    let trace_id_by_target: HashMap<String, String> = cfgs
        .iter()
        .filter_map(|c| c.trace_id.as_ref().map(|t| (c.url.to_string(), t.clone())))
        .collect();

    // count=None → 무한 반복. 첫 실패에서 멈춘다.
    let mut handle = runner::spawn_probe_loop(cfgs, None, interval);
    let mut captured: Vec<ProbeResult> = Vec::new();
    let mut failing: Option<ProbeResult> = None;

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                handle.cancel.cancel();
                while handle.rx.recv().await.is_some() {}
                break;
            }
            recv = handle.rx.recv() => {
                match recv {
                    Some(result) => {
                        let is_failure = !result.is_pass();
                        captured.push(result.clone());
                        if is_failure {
                            // 첫 실패(네트워크 실패 또는 --expect 위반) — 트랩 발동.
                            failing = Some(result);
                            handle.cancel.cancel();
                            while handle.rx.recv().await.is_some() {}
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    record::save_session(&captured, &save_path)?;
    eprintln!("httprove: trap session saved to {save_path}");

    // ㊲ 트랩이 캡처한 결과도 후처리 플래그를 존중한다 (이전엔 조용히 무시됐음).
    // OTLP: 캡처된 각 프로브를 collector로 내보낸다 (도달 불가면 circuit-break).
    if args.otlp.is_some() {
        let mut circuit_open = false;
        for r in &captured {
            stream_otlp(r, args, &trace_id_by_target, &mut circuit_open).await;
        }
    }
    // HTML 리포트: 트랩 세션 전체를 리포트로도 쓴다.
    if let Some(path) = &args.report {
        let vctx = verdict::VerdictContext {
            warn: out_cfg.warn,
            cert_warn_days: out_cfg.cert_warn_days,
            baseline_total_ms: None,
        };
        let verdicts: Vec<types::Verdict> =
            captured.iter().map(|r| verdict::assess(r, &vctx)).collect();
        output::html::write_report(&captured, &verdicts, path)?;
        eprintln!("httprove: HTML report written to {path}");
    }

    if let Some(result) = &failing {
        eprintln!("httprove: trap triggered after {} probe(s)", captured.len());
        output::text::print_single(result, out_cfg);
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// ㊲ 프로브 1건을 OTLP collector로 즉시 내보낸다 (best-effort, 스트리밍).
///
/// --traceparent와 같은 trace-id를 재사용해 백엔드에서 상관되게 한다.
/// collector가 도달 불가(커넥트/타임아웃/핸드셰이크 실패)면 `circuit_open`을 세워, 이후
/// 프로브에서 매번 15s 커넥트 타임아웃을 누적하지 않도록 남은 export를 차단한다.
async fn stream_otlp(
    result: &ProbeResult,
    args: &Args,
    trace_id_by_target: &HashMap<String, String>,
    circuit_open: &mut bool,
) {
    let Some(endpoint) = &args.otlp else {
        return;
    };
    if *circuit_open {
        return;
    }
    let trace_id = trace_id_by_target.get(&result.target).map(String::as_str);
    if let Err(e) = otlp::export_otlp(result, endpoint, trace_id).await {
        eprintln!("httprove: otlp export failed: {e:#}");
        // 도달 불가로 보이는 실패면 회로를 열어 남은 프로브의 export를 멈춘다.
        let msg = format!("{e:#}").to_ascii_lowercase();
        if msg.contains("timed out")
            || msg.contains("connect to")
            || msg.contains("tls handshake")
            || msg.contains("http handshake")
        {
            *circuit_open = true;
            eprintln!("httprove: otlp collector unreachable — disabling further exports this run");
        }
    }
}

/// --since-good 기준 파일에 현재 정상 프로브를 기록한다 (load_probe 호환 포맷).
/// probe_json은 `{"type":"probe", ...}` 한 줄을 만들고, diff::load_probe가 그대로 읽는다.
fn persist_since_good(path: &str, good: &ProbeResult) -> anyhow::Result<()> {
    use anyhow::Context;
    let mut json = output::json::probe_json(good);
    json.push('\n');
    std::fs::write(path, json)
        .with_context(|| format!("failed to write since-good baseline {path}"))?;
    Ok(())
}

/// argv[0]에서 프로그램명(httprove/hpr)만 추출한다 (update 서브커맨드 usage 표시용).
fn program_name(argv: &[String]) -> String {
    argv.first()
        .and_then(|p| std::path::Path::new(p).file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("httprove")
        .to_string()
}
