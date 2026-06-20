//! CLI 인자 정의와 ProbeConfig 변환.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Parser;

use crate::types::{
    Expectations, HttpVersionPref, IpFamily, ProbeConfig, StatusExpect, WarnThresholds,
};

/// HTTP(S) service diagnostics for SREs.
///
/// Measures every phase of an HTTP request (DNS, TCP, TLS, server time,
/// download) like a waterfall, inspects TLS certificates, and can probe
/// continuously like ping. Supports plain CLI output, JSON, Prometheus
/// metrics, assertions for synthetic checks, and a live TUI.
///
/// Exit codes: 0 = all probes passed; 1 = network failure or hard error;
/// 3 = all probes succeeded but at least one --expect assertion failed.
#[derive(Debug, Parser)]
#[command(name = "httprove", version, about, max_term_width = 100)]
pub struct Args {
    /// Target URL(s) (scheme optional; defaults to https://).
    /// With --cert-check: host[:port], URL, or @file with one host per line.
    #[arg(required = true, value_name = "TARGET")]
    pub targets: Vec<String>,

    /// HTTP method
    #[arg(short = 'X', long, default_value = "GET")]
    pub method: String,

    /// Extra request header "Key: Value" (repeatable)
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    pub headers: Vec<String>,

    /// Request body
    #[arg(short = 'd', long, value_name = "BODY")]
    pub data: Option<String>,

    /// Number of probes per target; 0 = run until Ctrl-C [default: 1]
    #[arg(short, long, value_name = "N")]
    pub count: Option<u64>,

    /// Seconds between probe starts (per target)
    #[arg(short, long, default_value_t = 1.0, value_name = "SECS")]
    pub interval: f64,

    /// Per-probe timeout in seconds (covers all redirect hops)
    #[arg(short, long, default_value_t = 10.0, value_name = "SECS")]
    pub timeout: f64,

    /// Follow 3xx redirects
    #[arg(short = 'L', long, conflicts_with = "keepalive")]
    pub follow: bool,

    /// Maximum redirects to follow (with -L)
    #[arg(long, default_value_t = 10, value_name = "N")]
    pub max_redirects: u32,

    /// Reuse one connection across probes (measures pure server time;
    /// dns/tcp/tls appear only on the first probe and reconnects)
    #[arg(long)]
    pub keepalive: bool,

    /// Resolve host to IPv4 only
    #[arg(short = '4', long, conflicts_with = "ipv6")]
    pub ipv4: bool,

    /// Resolve host to IPv6 only
    #[arg(short = '6', long)]
    pub ipv6: bool,

    /// Skip DNS and connect to this IP (Host/SNI still taken from URL)
    #[arg(long, value_name = "IP")]
    pub resolve: Option<IpAddr>,

    /// Skip TLS certificate verification (chain is still reported)
    #[arg(short = 'k', long)]
    pub insecure: bool,

    /// Force HTTP/1.1 (disable ALPN h2)
    #[arg(long)]
    pub http1: bool,

    /// JSON output: one object per probe (NDJSON) plus a final summary
    #[arg(long, conflicts_with = "tui")]
    pub json: bool,

    /// Live TUI dashboard (implies continuous probing unless -c is given)
    // TUI는 run_cli_mode 전에 반환하므로 후처리/판정/조사 플래그는 무시된다 — 거부한다.
    #[arg(long, conflicts_with_all = [
        "verdict", "explain", "check_chain", "record", "report", "on_change",
        "otlp", "since_good", "annotate_deploy", "fanout", "all_families", "via",
    ])]
    pub tui: bool,

    /// Print a Prometheus textfile-collector snapshot instead of the
    /// human summary (use with -c; pipe to *.prom)
    #[arg(long, conflicts_with_all = ["tui", "json"])]
    pub prom: bool,

    /// Exporter mode: probe forever and serve /metrics on this address
    /// (e.g. 0.0.0.0:9912)
    // exporter는 자체 무한 루프로 run_cli_mode 전에 반환하므로 후처리/판정/조사 플래그를
    // 무시한다 — 거부한다.
    #[arg(long, value_name = "ADDR",
          conflicts_with_all = [
              "tui", "json", "prom", "save", "compare", "cert_check", "count",
              "verdict", "explain", "check_chain", "trap", "record", "report",
              "on_change", "otlp", "since_good", "annotate_deploy",
              "fanout", "all_families", "via",
          ])]
    pub listen: Option<SocketAddr>,

    /// Batch certificate expiry check for the given targets
    // cert-check은 run() 최상단에서 반환하므로 프로브 후처리/판정/조사 플래그를 무시한다.
    #[arg(long = "cert-check",
          conflicts_with_all = [
              "tui", "follow", "keepalive", "save", "compare", "prom",
              "verdict", "explain", "check_chain", "trap", "record", "report",
              "on_change", "otlp", "traceparent", "since_good", "annotate_deploy",
              "fanout", "all_families", "via",
          ])]
    pub cert_check: bool,

    /// Save run statistics to a baseline file (JSON)
    #[arg(long, value_name = "PATH", conflicts_with = "tui")]
    pub save: Option<String>,

    /// Compare run statistics against a saved baseline file
    #[arg(long, value_name = "PATH", conflicts_with = "tui")]
    pub compare: Option<String>,

    /// Expected status codes, comma-separated; exact ("200,301") or
    /// class ("2xx,3xx"). Violations exit 3.
    #[arg(long = "expect-status", value_name = "CODES")]
    pub expect_status: Option<String>,

    /// Substring the (final) response body must contain
    #[arg(long = "expect-body", value_name = "SUBSTR")]
    pub expect_body: Option<String>,

    /// Maximum acceptable TTFB in milliseconds
    #[arg(long = "expect-ttfb", value_name = "MS")]
    pub expect_ttfb: Option<f64>,

    /// Maximum acceptable total probe time in milliseconds
    #[arg(long = "expect-total", value_name = "MS")]
    pub expect_total: Option<f64>,

    /// Minimum days the leaf certificate must remain valid
    #[arg(long = "expect-cert-days", value_name = "DAYS")]
    pub expect_cert_days: Option<i64>,

    /// Latency warning threshold "phase=ms" (repeatable; phase ∈
    /// dns,tcp,tls,ttfb,dl,total). >=1x yellow, >=2x red in output.
    #[arg(long = "warn", value_name = "PHASE=MS")]
    pub warn: Vec<String>,

    /// Warn when the certificate expires within N days
    #[arg(long, default_value_t = 30, value_name = "DAYS")]
    pub cert_warn: i64,

    /// Show response headers (single-probe mode)
    #[arg(short, long)]
    pub verbose: bool,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,

    // === v0.2 진단 확장 플래그 ============================================
    // 출력 부가 신호 (단발/요약 흐름에 덧붙는다).
    /// Append a PASS/DEGRADED/DOWN health verdict after each probe/summary
    #[arg(long)]
    pub verdict: bool,

    /// Print a plain-language explanation of each probe result
    #[arg(long)]
    pub explain: bool,

    /// Print an A–F TLS connection security grade (protocol/cipher/kx/HSTS/chain)
    #[arg(long = "tls-grade")]
    pub tls_grade: bool,

    /// Audit CDN/cache efficiency from response headers (HIT/MISS, age, anti-patterns)
    #[arg(long = "cache-audit")]
    pub cache_audit: bool,

    /// Watch mode: POST a JSON alert to this URL when a probe breaches (verdict != PASS)
    #[arg(long = "on-breach", value_name = "URL")]
    pub on_breach: Option<String>,

    /// Fire --on-breach only after N consecutive breaches
    #[arg(long = "breach-after", default_value_t = 1, value_name = "N")]
    pub breach_after: u32,

    /// Suppress repeat --on-breach alerts for this many seconds
    #[arg(long, default_value_t = 60.0, value_name = "SECS")]
    pub cooldown: f64,

    /// Also POST an alert when the target recovers to PASS
    #[arg(long = "on-recover")]
    pub on_recover: bool,

    // 조사(investigation) 모드 — 단발성, 자체 종료 코드 (standalone-ish).
    // 이 모드들은 자체 출력/종료 코드로 일찍 반환하므로, 후처리/판정 플래그를 함께 주면
    // 조용히 무시된다 — clap 단에서 거부해 사용자가 no-op 조합을 만들지 않게 한다.
    /// Probe every resolved A/AAAA address individually and flag outliers
    #[arg(long, conflicts_with_all = [
        "verdict", "explain", "check_chain", "trap", "record", "report",
        "on_change", "otlp", "since_good", "annotate_deploy", "all_families", "via",
    ])]
    pub fanout: bool,

    /// Probe once forced IPv4 and once forced IPv6, comparing each phase
    #[arg(long = "all-families", conflicts_with_all = [
        "verdict", "explain", "check_chain", "trap", "record", "report",
        "on_change", "otlp", "since_good", "annotate_deploy", "via",
    ])]
    pub all_families: bool,

    /// Resolve via these DNS servers (comma-separated IPs) and compare POPs
    #[arg(long, value_name = "IPS", conflicts_with_all = [
        "verdict", "explain", "check_chain", "trap", "record", "report",
        "on_change", "otlp", "since_good", "annotate_deploy",
    ])]
    pub via: Option<String>,

    /// EDNS client-subnet for --via (e.g. "203.0.113.0/24")
    #[arg(long, value_name = "CIDR")]
    pub ecs: Option<String>,

    // 인증서 체인 심화.
    /// Analyze chain completeness and attempt AIA repair
    #[arg(long = "check-chain")]
    pub check_chain: bool,

    // 캡처/기록/리포트.
    /// Capture trap: probe until the first failure, then save the session
    // 트랩은 record/report/otlp는 존중하지만(캡처 결과에 적용), 판정/변경탐지 플래그는
    // 자체 흐름에서 무시하므로 그것들과는 충돌시킨다. tui/json/listen과도 출력 모드가 다르다.
    #[arg(long, conflicts_with_all = [
        "verdict", "explain", "check_chain", "on_change", "since_good",
        "annotate_deploy", "tui", "json", "listen",
    ])]
    pub trap: bool,

    /// Record every probe of this run to a session file (JSON)
    #[arg(long, value_name = "PATH")]
    pub record: Option<String>,

    /// Write a self-contained HTML report to this path
    #[arg(long, value_name = "PATH")]
    pub report: Option<String>,

    /// Exit non-zero only when the service fingerprint changed (with --since-good)
    #[arg(long = "on-change")]
    pub on_change: bool,

    // 텔레메트리.
    /// Export each probe as OTLP/HTTP traces to this collector endpoint
    #[arg(long, value_name = "ENDPOINT")]
    pub otlp: Option<String>,

    /// Emit a W3C traceparent header on each request
    #[arg(long)]
    pub traceparent: bool,

    // 변경 탐지 / 배포 주석.
    /// Annotate fingerprint change vs this saved probe (deploy verification)
    #[arg(long = "annotate-deploy", value_name = "PATH")]
    pub annotate_deploy: Option<String>,

    /// Compare against this last-known-good probe JSON
    #[arg(long = "since-good", value_name = "PATH")]
    pub since_good: Option<String>,

    /// SLO target ratio in (0,1), e.g. 0.999 — exported as httprove_slo_target_ratio
    /// to parameterize burn-rate alert rules (burn calc stays in PromQL).
    #[arg(long, value_name = "RATIO")]
    pub slo: Option<f64>,

    /// Apdex satisfaction threshold T in ms — exports apdex_satisfied/tolerating_total
    /// counters (satisfied: total<=T, tolerating: T<total<=4T).
    #[arg(long = "apdex-threshold", value_name = "MS")]
    pub apdex_threshold: Option<f64>,
}

impl Args {
    /// 모든 타깃 URL을 정규화해 ProbeConfig 목록을 만든다 (--cert-check 외 모드).
    pub fn to_probe_configs(&self) -> anyhow::Result<Vec<ProbeConfig>> {
        let expect = self.parse_expectations()?;

        if self.timeout <= 0.0 || !self.timeout.is_finite() {
            bail!("--timeout must be a positive finite number");
        }
        if self.interval < 0.0 || !self.interval.is_finite() {
            bail!("--interval must be a non-negative finite number");
        }
        // SLO는 burn-rate 룰의 (1-SLO) 상수가 되므로 0.999 vs 99.9 단위 혼동을 하드 차단한다.
        if let Some(slo) = self.slo
            && !(slo > 0.0 && slo < 1.0)
        {
            bail!("--slo must be a ratio in (0, 1), e.g. 0.999 (not 99.9 or 99.9%)");
        }
        if let Some(t) = self.apdex_threshold
            && (t <= 0.0 || !t.is_finite())
        {
            bail!("--apdex-threshold must be a positive finite number of milliseconds");
        }

        let mut headers = Vec::new();
        for h in &self.headers {
            let (k, v) = h
                .split_once(':')
                .with_context(|| format!("invalid header (expected \"Key: Value\"): {h}"))?;
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }

        let ip_family = if self.ipv4 {
            IpFamily::V4
        } else if self.ipv6 {
            IpFamily::V6
        } else {
            IpFamily::Auto
        };

        let mut cfgs = Vec::with_capacity(self.targets.len());
        // 결과 라우팅/통계/exporter가 정규화된 URL 문자열을 키로 쓰므로, 정규화 후
        // 충돌하는 타깃(예: "example.com"과 "EXAMPLE.com:443/")은 한 슬롯으로
        // 합쳐져 통계가 오염된다 — 중복은 여기서 하드 에러로 거른다.
        let mut seen: HashSet<String> = HashSet::with_capacity(self.targets.len());
        for raw in &self.targets {
            let raw = raw.trim();
            let with_scheme = if raw.contains("://") {
                raw.to_string()
            } else {
                format!("https://{raw}")
            };
            let url =
                url::Url::parse(&with_scheme).with_context(|| format!("invalid URL: {raw}"))?;
            match url.scheme() {
                "http" | "https" => {}
                other => bail!("unsupported scheme: {other} (only http/https)"),
            }
            if url.host_str().is_none() {
                bail!("URL has no host: {raw}");
            }
            if !seen.insert(url.to_string()) {
                bail!("duplicate target after normalization: {raw} -> {url}");
            }

            cfgs.push(ProbeConfig {
                url,
                method: self.method.to_uppercase(),
                headers: headers.clone(),
                body: self.data.clone(),
                timeout: Duration::from_secs_f64(self.timeout),
                resolve: self.resolve,
                ip_family,
                // --check-chain은 검증 실패(UnknownIssuer 등)로 핸드셰이크가 끊겨도 체인을
                // 수집해 분석해야 하므로 무검증 핸드셰이크를 강제한다 (체인 진단 목적).
                insecure: self.insecure || self.check_chain,
                http_version: if self.http1 {
                    HttpVersionPref::Http1
                } else {
                    HttpVersionPref::Auto
                },
                max_redirects: if self.follow { self.max_redirects } else { 0 },
                keep_alive: self.keepalive,
                expect: expect.clone(),
                // traceparent trace-id는 run()에서 --traceparent가 켜졌을 때 채운다.
                trace_id: None,
            });
        }
        Ok(cfgs)
    }

    /// `--expect-*` 플래그들을 Expectations로 변환한다.
    fn parse_expectations(&self) -> anyhow::Result<Expectations> {
        let status = match &self.expect_status {
            None => None,
            Some(spec) => {
                let mut list = Vec::new();
                for part in spec.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    // "2xx" 클래스 표기 또는 정확한 코드.
                    let lower = part.to_ascii_lowercase();
                    if let Some(class) = lower.strip_suffix("xx") {
                        let class: u16 = class
                            .parse()
                            .ok()
                            .filter(|c| (1..=5).contains(c))
                            .with_context(|| format!("invalid status class: {part}"))?;
                        list.push(StatusExpect::Class(class));
                    } else {
                        let code: u16 = part
                            .parse()
                            .ok()
                            .filter(|c| (100..=599).contains(c))
                            .with_context(|| format!("invalid status code: {part}"))?;
                        list.push(StatusExpect::Exact(code));
                    }
                }
                if list.is_empty() {
                    bail!("--expect-status has no valid codes: {spec}");
                }
                Some(list)
            }
        };

        for (name, v) in [
            ("--expect-ttfb", self.expect_ttfb),
            ("--expect-total", self.expect_total),
        ] {
            if let Some(v) = v
                && (v <= 0.0 || !v.is_finite())
            {
                bail!("{name} must be a positive finite number");
            }
        }

        Ok(Expectations {
            status,
            body_contains: self.expect_body.clone(),
            max_ttfb_ms: self.expect_ttfb,
            max_total_ms: self.expect_total,
            min_cert_days: self.expect_cert_days,
        })
    }

    /// `--via` CSV(쉼표 구분 IP)를 IpAddr 목록으로 파싱한다 (dns::run_via_resolvers용).
    /// --via가 없으면 빈 Vec. 빈 항목/공백은 건너뛰고, 잘못된 IP는 하드 에러.
    pub fn parse_via_resolvers(&self) -> anyhow::Result<Vec<IpAddr>> {
        let mut resolvers = Vec::new();
        let Some(spec) = &self.via else {
            return Ok(resolvers);
        };
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let ip: IpAddr = part
                .parse()
                .with_context(|| format!("invalid --via resolver IP: {part}"))?;
            resolvers.push(ip);
        }
        if resolvers.is_empty() {
            bail!("--via has no valid resolver IPs: {spec}");
        }
        Ok(resolvers)
    }

    /// `--warn phase=ms` 목록을 WarnThresholds로 변환한다.
    pub fn parse_warn(&self) -> anyhow::Result<WarnThresholds> {
        let mut warn = WarnThresholds::default();
        for spec in &self.warn {
            let (phase, ms) = spec
                .split_once('=')
                .with_context(|| format!("invalid --warn (expected phase=ms): {spec}"))?;
            let ms: f64 = ms
                .trim()
                .parse()
                .ok()
                .filter(|v: &f64| *v > 0.0 && v.is_finite())
                .with_context(|| format!("invalid --warn threshold: {spec}"))?;
            let slot = match phase.trim().to_ascii_lowercase().as_str() {
                "dns" => &mut warn.dns,
                "tcp" => &mut warn.tcp,
                "tls" => &mut warn.tls,
                "ttfb" => &mut warn.ttfb,
                "dl" | "download" => &mut warn.download,
                "total" => &mut warn.total,
                other => bail!("unknown --warn phase: {other} (dns,tcp,tls,ttfb,dl,total)"),
            };
            *slot = Some(ms);
        }
        Ok(warn)
    }
}
