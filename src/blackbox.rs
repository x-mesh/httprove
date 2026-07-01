//! blackbox_exporter modules YAML 호환 (--blackbox-config).
//!
//! 기존 blackbox_exporter의 `modules:` 설정(http prober)을 읽어 httprove ProbeConfig +
//! Expectations로 변환한다. `--listen`과 함께 쓰면 `/probe?target=&module=` 엔드포인트로
//! Prometheus가 기존처럼 스크레이프하되, 각 프로브에 httprove의 단계별 워터폴·TLS·verdict가
//! 함께 붙는 drop-in 업그레이드가 된다.
//!
//! 지원 범위는 http prober의 valid_status_codes, method, headers, no_follow_redirects,
//! preferred_ip_protocol, fail_if_body_not_matches_regexp(정규식→부분 문자열로 근사)이다.
//! tcp/dns/icmp prober와 정규식 정밀 매칭은 미지원(http 중심).

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::types::{
    Expectations, HttpVersionPref, IpFamily, ProbeConfig, ProbeResult, StatusExpect,
};

/// blackbox_exporter config 파일 (modules만 사용).
#[derive(Debug, Deserialize)]
pub struct BlackboxConfig {
    #[serde(default)]
    pub modules: HashMap<String, Module>,
}

/// 한 모듈. prober=http만 변환을 지원한다.
#[derive(Debug, Deserialize)]
pub struct Module {
    #[serde(default)]
    pub prober: String,
    /// Go duration 문자열(예 "5s"). None이면 호출자 기본 타임아웃.
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub http: HttpModule,
}

/// http prober 설정 (blackbox 필드 일부).
#[derive(Debug, Deserialize, Default)]
pub struct HttpModule {
    #[serde(default)]
    pub valid_status_codes: Vec<u16>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub no_follow_redirects: bool,
    /// "ip4" | "ip6" | "" (auto).
    #[serde(default)]
    pub preferred_ip_protocol: String,
    /// 바디에 반드시 포함돼야 하는 패턴(정규식→부분 문자열 근사, 첫 항목만 사용).
    #[serde(default)]
    pub fail_if_body_not_matches_regexp: Vec<String>,
}

impl BlackboxConfig {
    /// YAML 파일을 파싱한다.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read blackbox config {path}"))?;
        serde_yaml_ng::from_str(&text).with_context(|| format!("parse blackbox config {path}"))
    }

    /// 모듈 이름으로 조회.
    pub fn module(&self, name: &str) -> Option<&Module> {
        self.modules.get(name)
    }
}

/// blackbox 모듈 + 타깃을 httprove ProbeConfig로 변환한다.
/// http prober가 아니면 에러. target은 scheme이 없으면 https:// 를 붙인다.
pub fn to_probe_config(
    module: &Module,
    target: &str,
    default_timeout: Duration,
) -> anyhow::Result<ProbeConfig> {
    if !module.prober.is_empty() && module.prober != "http" {
        bail!(
            "unsupported blackbox prober '{}' (only http)",
            module.prober
        );
    }
    let h = &module.http;

    let with_scheme = if target.contains("://") {
        target.to_string()
    } else {
        format!("https://{target}")
    };
    let url = url::Url::parse(&with_scheme)
        .with_context(|| format!("invalid blackbox target: {target}"))?;

    let method = h
        .method
        .clone()
        .unwrap_or_else(|| "GET".to_string())
        .to_uppercase();
    let headers: Vec<(String, String)> = h
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let ip_family = match h.preferred_ip_protocol.as_str() {
        "ip4" => IpFamily::V4,
        "ip6" => IpFamily::V6,
        _ => IpFamily::Auto,
    };

    // valid_status_codes가 비면 blackbox 기본은 2xx.
    let status = if h.valid_status_codes.is_empty() {
        vec![StatusExpect::Class(2)]
    } else {
        h.valid_status_codes
            .iter()
            .map(|c| StatusExpect::Exact(*c))
            .collect()
    };

    let expect = Expectations {
        status: Some(status),
        // blackbox는 정규식이지만 httprove는 부분 문자열 — 첫 패턴을 근사로 쓴다.
        body_contains: h.fail_if_body_not_matches_regexp.first().cloned(),
        max_ttfb_ms: None,
        max_total_ms: None,
        min_cert_days: None,
    };

    let timeout = parse_go_duration(module.timeout.as_deref()).unwrap_or(default_timeout);

    Ok(ProbeConfig {
        url,
        method,
        headers,
        body: None,
        timeout,
        resolve: None,
        dns_servers: Vec::new(),
        ecs: None,
        ip_family,
        insecure: false,
        http_version: HttpVersionPref::Auto,
        max_redirects: if h.no_follow_redirects { 0 } else { 10 },
        keep_alive: false,
        expect,
        trace_id: None,
    })
}

/// Go duration 문자열("5s", "1500ms", "1m")을 근사 파싱한다. 실패하면 None.
fn parse_go_duration(s: Option<&str>) -> Option<Duration> {
    let s = s?.trim();
    let split = s.find(|c: char| c.is_alphabetic())?;
    let (num, unit) = s.split_at(split);
    let n: f64 = num.trim().parse().ok()?;
    let secs = match unit {
        "ms" => n / 1000.0,
        "s" => n,
        "m" => n * 60.0,
        "h" => n * 3600.0,
        _ => return None,
    };
    Some(Duration::from_secs_f64(secs))
}

/// 단발 ProbeResult를 blackbox_exporter 호환 메트릭 텍스트로 렌더한다. 기존 blackbox
/// alert/dashboard가 그대로 동작하도록 probe_* 이름을 따른다.
pub fn render_blackbox(result: &ProbeResult) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let success = result.is_success() && result.expect_failures.is_empty();
    let _ = writeln!(
        out,
        "# HELP probe_success Whether the probe succeeded (network ok + assertions passed)"
    );
    let _ = writeln!(out, "# TYPE probe_success gauge");
    let _ = writeln!(out, "probe_success {}", u8::from(success));
    let _ = writeln!(
        out,
        "# HELP probe_duration_seconds Total probe time in seconds"
    );
    let _ = writeln!(out, "# TYPE probe_duration_seconds gauge");
    let _ = writeln!(out, "probe_duration_seconds {}", result.total_ms / 1000.0);

    if let Some(status) = result.status() {
        let _ = writeln!(out, "# TYPE probe_http_status_code gauge");
        let _ = writeln!(out, "probe_http_status_code {status}");
    }
    if let Some(hop) = result.final_hop() {
        let t = &hop.timings;
        let _ = writeln!(out, "# TYPE probe_http_duration_seconds gauge");
        if let Some(dns) = t.dns_ms {
            let _ = writeln!(
                out,
                "probe_http_duration_seconds{{phase=\"resolve\"}} {}",
                dns / 1000.0
            );
        }
        let _ = writeln!(
            out,
            "probe_http_duration_seconds{{phase=\"connect\"}} {}",
            t.tcp_ms / 1000.0
        );
        if let Some(tls) = t.tls_ms {
            let _ = writeln!(
                out,
                "probe_http_duration_seconds{{phase=\"tls\"}} {}",
                tls / 1000.0
            );
        }
        let _ = writeln!(
            out,
            "probe_http_duration_seconds{{phase=\"processing\"}} {}",
            t.ttfb_ms / 1000.0
        );
        let _ = writeln!(
            out,
            "probe_http_duration_seconds{{phase=\"transfer\"}} {}",
            t.download_ms / 1000.0
        );
        let _ = writeln!(out, "# TYPE probe_http_ssl gauge");
        let _ = writeln!(out, "probe_http_ssl {}", u8::from(hop.tls.is_some()));
    }
    if let Some(cert) = result.leaf_cert() {
        let _ = writeln!(out, "# TYPE probe_ssl_earliest_cert_expiry gauge");
        let _ = writeln!(
            out,
            "probe_ssl_earliest_cert_expiry {}",
            cert.not_after.timestamp()
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
modules:
  http_2xx:
    prober: http
    timeout: 5s
    http:
      valid_status_codes: [200, 204]
      method: POST
      headers:
        Accept: application/json
      no_follow_redirects: true
      preferred_ip_protocol: ip4
  http_default:
    prober: http
    http: {}
  icmp_mod:
    prober: icmp
"#;

    #[test]
    fn parses_modules() {
        let cfg: BlackboxConfig = serde_yaml_ng::from_str(YAML).unwrap();
        assert_eq!(cfg.modules.len(), 3);
        assert!(cfg.module("http_2xx").is_some());
    }

    #[test]
    fn converts_http_module() {
        let cfg: BlackboxConfig = serde_yaml_ng::from_str(YAML).unwrap();
        let m = cfg.module("http_2xx").unwrap();
        let pc = to_probe_config(m, "example.com", Duration::from_secs(10)).unwrap();
        assert_eq!(pc.url.as_str(), "https://example.com/");
        assert_eq!(pc.method, "POST");
        assert_eq!(pc.ip_family, IpFamily::V4);
        assert_eq!(pc.max_redirects, 0); // no_follow_redirects
        assert_eq!(pc.timeout, Duration::from_secs(5));
        assert_eq!(
            pc.headers,
            vec![("Accept".to_string(), "application/json".to_string())]
        );
        let status = pc.expect.status.unwrap();
        assert_eq!(status.len(), 2);
        assert!(status.iter().any(|s| s.matches(200)));
        assert!(status.iter().any(|s| s.matches(204)));
    }

    #[test]
    fn default_module_is_2xx_get() {
        let cfg: BlackboxConfig = serde_yaml_ng::from_str(YAML).unwrap();
        let m = cfg.module("http_default").unwrap();
        let pc = to_probe_config(m, "https://x.test/", Duration::from_secs(10)).unwrap();
        assert_eq!(pc.method, "GET");
        assert_eq!(pc.max_redirects, 10);
        let status = pc.expect.status.unwrap();
        assert!(status.iter().any(|s| s.matches(200)));
        assert!(status.iter().any(|s| s.matches(299)));
        assert!(!status.iter().any(|s| s.matches(404)));
    }

    #[test]
    fn non_http_prober_rejected() {
        let cfg: BlackboxConfig = serde_yaml_ng::from_str(YAML).unwrap();
        let m = cfg.module("icmp_mod").unwrap();
        assert!(to_probe_config(m, "x.test", Duration::from_secs(10)).is_err());
    }

    #[test]
    fn go_duration_parsing() {
        assert_eq!(parse_go_duration(Some("5s")), Some(Duration::from_secs(5)));
        assert_eq!(
            parse_go_duration(Some("1500ms")),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(
            parse_go_duration(Some("2m")),
            Some(Duration::from_secs(120))
        );
        assert_eq!(parse_go_duration(None), None);
        assert_eq!(parse_go_duration(Some("bogus")), None);
    }
}
