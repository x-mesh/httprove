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

    /// Pin resolution instead of using DNS. Either a bare IP (applies to every
    /// target) or curl-style HOST:PORT:ADDR (per host, repeatable) — an in-tool
    /// /etc/hosts. Host/SNI stay from the URL. Takes precedence over --dns.
    #[arg(long, value_name = "IP|HOST:PORT:ADDR")]
    pub resolve: Vec<String>,

    /// Resolve targets through these DNS servers instead of the system resolver
    /// (comma-separated IP or IP:PORT, tried in order). Combine with --ecs for
    /// EDNS client-subnet. Works with normal/keepalive/json/prom/tui/exporter modes.
    #[arg(long, value_name = "IPS", conflicts_with_all = [
        "via", "fanout", "all_families", "cert_check", "blackbox_config",
    ])]
    pub dns: Option<String>,

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

    /// Look up ASN/org/country (Team Cymru DNS) + reverse DNS for the connected IP
    #[arg(long)]
    pub asn: bool,

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

    /// Run probes from a blackbox_exporter modules YAML (http prober) instead of CLI flags.
    /// With --listen, serves a blackbox-compatible /probe?target=&module= endpoint.
    #[arg(long = "blackbox-config", value_name = "FILE")]
    pub blackbox_config: Option<String>,

    /// Blackbox module name to use (with --blackbox-config; default: http_2xx)
    #[arg(long, value_name = "NAME")]
    pub module: Option<String>,

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

    /// EDNS client-subnet for --dns/--via (e.g. "203.0.113.0/24")
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

/// `--resolve` 항목들을 파싱한 정적 오버라이드 집합 (DNS를 건너뛰고 고정 IP로 연결).
#[derive(Debug, Default)]
pub struct ResolveOverrides {
    /// bare IP 형태 — 모든 타깃에 적용되는 전역 오버라이드.
    global: Option<IpAddr>,
    /// curl식 host:port:addr — 특정 (host 소문자, port)를 이 IP로 고정.
    per_host: Vec<((String, u16), IpAddr)>,
}

impl ResolveOverrides {
    /// 주어진 host/port에 적용할 오버라이드 IP를 찾는다 (per-host 우선, 없으면 전역).
    pub fn lookup(&self, host: Option<&str>, port: u16) -> Option<IpAddr> {
        if let Some(h) = host {
            let key = h.to_ascii_lowercase();
            if let Some((_, ip)) = self
                .per_host
                .iter()
                .find(|((hh, pp), _)| *hh == key && *pp == port)
            {
                return Some(*ip);
            }
        }
        self.global
    }
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

        // --dns 서버 목록과 --resolve 오버라이드를 미리 파싱한다 (형식 오류는 하드 에러).
        let dns_servers = self.parse_dns_servers()?;
        let resolve_overrides = self.parse_resolve_overrides()?;
        // --ecs는 커스텀 리졸버(--dns/--via) 경로에서만 적용된다. 그 없이 주면 조용히
        // 무시되므로(silent no-op) 하드 에러로 거부하고, 있을 때만 CIDR 형식을 미리 검증한다.
        if let Some(cidr) = &self.ecs {
            if self.dns.is_none() && self.via.is_none() {
                bail!("--ecs only applies to --dns or --via; pass one of them (or drop --ecs)");
            }
            crate::dns::validate_ecs(cidr)?;
        }

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

            // 이 타깃에 적용할 정적 오버라이드: per-host(host:port) 우선, 없으면 전역 bare-IP.
            let resolve =
                resolve_overrides.lookup(url.host_str(), url.port_or_known_default().unwrap_or(0));

            cfgs.push(ProbeConfig {
                url,
                method: self.method.to_uppercase(),
                headers: headers.clone(),
                body: self.data.clone(),
                timeout: Duration::from_secs_f64(self.timeout),
                resolve,
                dns_servers: dns_servers.clone(),
                ecs: self.ecs.clone(),
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

    /// `--dns` CSV(IP 또는 IP:PORT)를 SocketAddr 목록으로 파싱한다 (일반 프로브 경로용).
    /// bare IP는 포트 53으로 보정한다. --dns가 없으면 빈 Vec.
    pub fn parse_dns_servers(&self) -> anyhow::Result<Vec<SocketAddr>> {
        let mut servers = Vec::new();
        let Some(spec) = &self.dns else {
            return Ok(servers);
        };
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            // IP:PORT를 먼저 시도하고, 실패하면 bare IP(→ 53)로 본다. IPv6에 포트를
            // 붙이려면 [::1]:5353 형식을 써야 한다 (bare 2001:db8::1은 포트 53).
            let addr = if let Ok(sa) = part.parse::<SocketAddr>() {
                sa
            } else if let Ok(ip) = part.parse::<IpAddr>() {
                SocketAddr::new(ip, 53)
            } else {
                bail!("invalid --dns server (expected IP or IP:PORT): {part}");
            };
            if !servers.contains(&addr) {
                servers.push(addr);
            }
        }
        if servers.is_empty() {
            bail!("--dns has no valid servers: {spec}");
        }
        Ok(servers)
    }

    /// `--resolve` 항목들을 전역 IP / per-host 매핑으로 파싱한다.
    /// - bare IP("203.0.113.5"): 전역 오버라이드 (모든 타깃).
    /// - curl식 "host:port:addr": per-host 오버라이드. addr가 IPv6일 수 있으므로
    ///   앞에서 두 번만 분리한다(splitn(3)). 전역 IP를 둘 이상 주거나 같은
    ///   host:port를 중복 지정하면 하드 에러.
    pub fn parse_resolve_overrides(&self) -> anyhow::Result<ResolveOverrides> {
        let mut out = ResolveOverrides::default();
        for raw in &self.resolve {
            let s = raw.trim();
            // --resolve는 반복 플래그(항목당 값 하나)이므로 빈 값은 실수다 — 조용히
            // 넘기면 의도한 고정이 사라져 엉뚱한 백엔드를 친다. 하드 에러로 거부한다.
            if s.is_empty() {
                bail!("--resolve given an empty value");
            }
            // 1) bare IP → 전역. (IPv6 리터럴도 여기서 잡으므로 host:port:addr보다 먼저.)
            if let Ok(ip) = s.parse::<IpAddr>() {
                if out.global.replace(ip).is_some() {
                    bail!("--resolve given more than one global IP");
                }
                continue;
            }
            // 2) curl식 host:port:addr.
            let mut it = s.splitn(3, ':');
            let host = it.next().unwrap_or("").trim();
            let (Some(port), Some(addr)) = (it.next(), it.next()) else {
                bail!("invalid --resolve (expected IP or HOST:PORT:ADDR): {raw}");
            };
            if host.is_empty() {
                bail!("--resolve has empty host: {raw}");
            }
            let port: u16 = port
                .trim()
                .parse()
                .with_context(|| format!("invalid --resolve port in {raw}"))?;
            // addr는 curl처럼 대괄호 IPv6([2001:db8::1])도 허용한다 (IpAddr::from_str은
            // 대괄호를 안 받으므로 감싼 [] 한 쌍을 벗겨낸다).
            let addr_str = addr.trim();
            let addr_str = addr_str
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(addr_str);
            let addr: IpAddr = addr_str
                .parse()
                .with_context(|| format!("invalid --resolve address in {raw}"))?;
            let key = (host.to_ascii_lowercase(), port);
            if out.per_host.iter().any(|(k, _)| *k == key) {
                bail!("duplicate --resolve entry for {host}:{port}");
            }
            out.per_host.push((key, addr));
        }
        Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// clap으로 Args를 파싱한다 (기본 바이너리명 + 인자). 실패는 패닉.
    fn args(argv: &[&str]) -> Args {
        let mut v = vec!["httprove"];
        v.extend_from_slice(argv);
        Args::try_parse_from(v).expect("parse args")
    }

    #[test]
    fn parse_dns_servers_bare_and_port() {
        let a = args(&["ex.com", "--dns", "1.1.1.1,8.8.8.8:5353"]);
        let servers = a.parse_dns_servers().expect("dns");
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0], "1.1.1.1:53".parse().unwrap());
        assert_eq!(servers[1], "8.8.8.8:5353".parse().unwrap());
    }

    #[test]
    fn parse_dns_servers_ipv6_bracket_and_bare() {
        let a = args(&["ex.com", "--dns", "2001:db8::1,[2001:db8::2]:5353"]);
        let servers = a.parse_dns_servers().expect("dns");
        assert_eq!(servers[0], "[2001:db8::1]:53".parse().unwrap());
        assert_eq!(servers[1], "[2001:db8::2]:5353".parse().unwrap());
    }

    #[test]
    fn parse_dns_servers_dedup_and_none() {
        let a = args(&["ex.com", "--dns", "1.1.1.1, 1.1.1.1 ,"]);
        assert_eq!(a.parse_dns_servers().expect("dns").len(), 1);
        // --dns 미지정이면 빈 Vec.
        assert!(args(&["ex.com"]).parse_dns_servers().unwrap().is_empty());
    }

    #[test]
    fn parse_dns_servers_invalid_errs() {
        assert!(
            args(&["ex.com", "--dns", "not-an-ip"])
                .parse_dns_servers()
                .is_err()
        );
        // 값은 있지만 전부 공백/빈 항목이면 에러.
        assert!(
            args(&["ex.com", "--dns", " , "])
                .parse_dns_servers()
                .is_err()
        );
    }

    #[test]
    fn resolve_global_bare_ip() {
        let ov = args(&["ex.com", "--resolve", "203.0.113.5"])
            .parse_resolve_overrides()
            .expect("resolve");
        assert_eq!(
            ov.lookup(Some("anything.com"), 443),
            Some("203.0.113.5".parse().unwrap())
        );
    }

    #[test]
    fn resolve_per_host_curl_form() {
        let ov = args(&["ex.com", "--resolve", "ex.com:443:203.0.113.5"])
            .parse_resolve_overrides()
            .expect("resolve");
        // 대소문자 무시 매칭.
        assert_eq!(
            ov.lookup(Some("EX.com"), 443),
            Some("203.0.113.5".parse().unwrap())
        );
        // 포트가 다르거나 다른 호스트면 매칭 안 됨(전역 없음).
        assert_eq!(ov.lookup(Some("ex.com"), 8443), None);
        assert_eq!(ov.lookup(Some("other.com"), 443), None);
    }

    #[test]
    fn resolve_per_host_ipv6_addr() {
        let ov = args(&["ex.com", "--resolve", "ex.com:443:2001:db8::1"])
            .parse_resolve_overrides()
            .expect("resolve");
        assert_eq!(
            ov.lookup(Some("ex.com"), 443),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn resolve_per_host_beats_global() {
        let ov = args(&[
            "a.com",
            "b.com",
            "--resolve",
            "9.9.9.9",
            "--resolve",
            "a.com:443:1.2.3.4",
        ])
        .parse_resolve_overrides()
        .expect("resolve");
        assert_eq!(
            ov.lookup(Some("a.com"), 443),
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(
            ov.lookup(Some("b.com"), 443),
            Some("9.9.9.9".parse().unwrap())
        );
    }

    #[test]
    fn resolve_errors() {
        // 전역 IP 둘 이상.
        assert!(
            args(&["ex.com", "--resolve", "1.1.1.1", "--resolve", "2.2.2.2"])
                .parse_resolve_overrides()
                .is_err()
        );
        // 같은 host:port 중복.
        assert!(
            args(&[
                "ex.com",
                "--resolve",
                "ex.com:443:1.1.1.1",
                "--resolve",
                "ex.com:443:2.2.2.2"
            ])
            .parse_resolve_overrides()
            .is_err()
        );
        // 형식/포트/주소 오류.
        assert!(
            args(&["ex.com", "--resolve", "ex.com:443"])
                .parse_resolve_overrides()
                .is_err()
        );
        assert!(
            args(&["ex.com", "--resolve", "ex.com:notaport:1.1.1.1"])
                .parse_resolve_overrides()
                .is_err()
        );
        assert!(
            args(&["ex.com", "--resolve", "ex.com:443:not-an-ip"])
                .parse_resolve_overrides()
                .is_err()
        );
    }

    #[test]
    fn to_probe_configs_wires_dns_and_resolve() {
        let cfgs = args(&[
            "https://a.com",
            "https://b.com",
            "--dns",
            "1.1.1.1",
            "--resolve",
            "a.com:443:10.0.0.1",
        ])
        .to_probe_configs()
        .expect("cfgs");
        assert_eq!(cfgs.len(), 2);
        // 두 타깃 모두 커스텀 DNS 서버를 받는다.
        for c in &cfgs {
            assert_eq!(c.dns_servers, vec!["1.1.1.1:53".parse().unwrap()]);
        }
        // a.com은 per-host 오버라이드로 resolve 고정, b.com은 없음.
        let a_cfg = cfgs
            .iter()
            .find(|c| c.url.host_str() == Some("a.com"))
            .unwrap();
        let b_cfg = cfgs
            .iter()
            .find(|c| c.url.host_str() == Some("b.com"))
            .unwrap();
        assert_eq!(a_cfg.resolve, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(b_cfg.resolve, None);
    }

    #[test]
    fn bare_ip_resolve_backward_compat() {
        // 기존 사용법: --resolve <IP> 하나 → 전역, 모든 타깃에 적용.
        let cfgs = args(&["https://ex.com", "--resolve", "203.0.113.9"])
            .to_probe_configs()
            .expect("cfgs");
        assert_eq!(cfgs[0].resolve, Some("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn dns_conflicts_with_investigation_modes() {
        // --dns는 자체 해석/조사 모드와 충돌한다 (silent no-op 방지).
        for other in [
            vec!["--via", "8.8.8.8"],
            vec!["--fanout"],
            vec!["--all-families"],
            vec!["--cert-check"],
        ] {
            let mut v = vec!["httprove", "ex.com", "--dns", "1.1.1.1"];
            v.extend_from_slice(&other);
            assert!(
                Args::try_parse_from(v).is_err(),
                "expected conflict with {other:?}"
            );
        }
    }

    #[test]
    fn resolve_empty_value_errs() {
        // 빈/공백 --resolve 값은 조용히 무시하지 않고 하드 에러 (하위호환: 옛 Option<IpAddr>도 거부).
        assert!(
            args(&["ex.com", "--resolve", ""])
                .parse_resolve_overrides()
                .is_err()
        );
        assert!(
            args(&["ex.com", "--resolve", "   "])
                .parse_resolve_overrides()
                .is_err()
        );
    }

    #[test]
    fn resolve_bracketed_ipv6_addr() {
        // curl식 대괄호 IPv6 addr도 허용한다.
        let ov = args(&["ex.com", "--resolve", "ex.com:443:[2001:db8::1]"])
            .parse_resolve_overrides()
            .expect("resolve");
        assert_eq!(
            ov.lookup(Some("ex.com"), 443),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn ecs_requires_dns_or_via() {
        // --ecs 단독은 무의미하므로 하드 에러 (--dns/--via 없이).
        assert!(
            args(&["https://ex.com", "--ecs", "203.0.113.0/24"])
                .to_probe_configs()
                .is_err()
        );
        // --dns와 함께면 통과하고 모든 cfg에 실린다.
        let cfgs = args(&[
            "https://ex.com",
            "--dns",
            "1.1.1.1",
            "--ecs",
            "203.0.113.0/24",
        ])
        .to_probe_configs()
        .expect("cfgs");
        assert_eq!(cfgs[0].ecs.as_deref(), Some("203.0.113.0/24"));
    }
}
