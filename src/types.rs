//! httprove 전역 공유 타입.
//!
//! 모든 모듈이 이 타입들을 통해서만 통신한다. 시간 값은 측정 직후 f64 밀리초로
//! 변환해 저장한다 (JSON 직렬화와 TUI 표시 단순화 목적).

use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// IP 패밀리 선택 (-4 / -6 플래그).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    Auto,
    V4,
    V6,
}

/// HTTP 버전 선호. Auto는 ALPN으로 h2/http1.1 협상, Http1은 http/1.1 강제.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersionPref {
    Auto,
    Http1,
}

/// 프로브 1회(리다이렉트 체인 전체)의 설정.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub url: url::Url,
    pub method: String,
    /// 추가 요청 헤더 (key, value).
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    /// 프로브 전체(모든 hop 포함) 타임아웃 예산.
    pub timeout: Duration,
    /// DNS를 건너뛰고 이 IP로 직접 연결 (SNI/Host는 URL 호스트 유지).
    pub resolve: Option<IpAddr>,
    pub ip_family: IpFamily,
    /// true면 TLS 인증서 검증을 생략 (체인 정보는 여전히 수집).
    pub insecure: bool,
    pub http_version: HttpVersionPref,
    /// 0이면 리다이렉트를 따라가지 않음.
    pub max_redirects: u32,
    /// 연결을 재사용하는 keep-alive 모드 (리다이렉트와 동시 사용 불가, cli에서 검증).
    pub keep_alive: bool,
    /// 프로브 결과에 적용할 어설션. 위반은 ProbeResult.expect_failures에 기록된다.
    pub expect: Expectations,
    /// --traceparent로 주입한 W3C trace-id(32 hex). OTLP export가 같은 trace-id를
    /// 재사용해 헤더와 내보낸 스팬의 trace를 백엔드에서 상관시킬 수 있게 한다. None이면
    /// traceparent 미사용(또는 export가 자체 trace-id를 만든다).
    pub trace_id: Option<String>,
}

/// `--expect-*` 어설션 집합. 모두 None이면 검사 안 함.
#[derive(Debug, Clone, Default)]
pub struct Expectations {
    /// 허용 상태 코드 목록 (최종 hop 기준).
    pub status: Option<Vec<StatusExpect>>,
    /// 최종 hop 응답 바디(최대 1 MiB 캡처)에 포함되어야 하는 부분 문자열.
    pub body_contains: Option<String>,
    /// TTFB 상한 (hop 합산, ms).
    pub max_ttfb_ms: Option<f64>,
    /// 프로브 전체 시간 상한 (ms).
    pub max_total_ms: Option<f64>,
    /// leaf 인증서 만료까지 최소 잔여 일수.
    pub min_cert_days: Option<i64>,
}

impl Expectations {
    pub fn is_empty(&self) -> bool {
        self.status.is_none()
            && self.body_contains.is_none()
            && self.max_ttfb_ms.is_none()
            && self.max_total_ms.is_none()
            && self.min_cert_days.is_none()
    }
}

/// 상태 코드 기대값: 정확한 코드 또는 클래스 (Class(2) = 2xx).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusExpect {
    Exact(u16),
    Class(u16),
}

impl StatusExpect {
    pub fn matches(&self, status: u16) -> bool {
        match self {
            StatusExpect::Exact(code) => status == *code,
            StatusExpect::Class(class) => status / 100 == *class,
        }
    }
}

impl std::fmt::Display for StatusExpect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatusExpect::Exact(code) => write!(f, "{code}"),
            StatusExpect::Class(class) => write!(f, "{class}xx"),
        }
    }
}

/// `--warn <phase>=<ms>` 임계값. 초과 시 출력에서 노랑(>=1x)/빨강(>=2x) 강조.
#[derive(Debug, Clone, Copy, Default)]
pub struct WarnThresholds {
    pub dns: Option<f64>,
    pub tcp: Option<f64>,
    pub tls: Option<f64>,
    pub ttfb: Option<f64>,
    pub download: Option<f64>,
    pub total: Option<f64>,
}

impl WarnThresholds {
    /// 계약(contract) API — 현재 호출처는 없지만 임계값 유무 판별용으로 유지.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.dns.is_none()
            && self.tcp.is_none()
            && self.tls.is_none()
            && self.ttfb.is_none()
            && self.download.is_none()
            && self.total.is_none()
    }
}

/// 임계값 대비 측정값의 경고 수준.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarnLevel {
    Ok,
    Warn,
    Crit,
}

impl WarnLevel {
    /// threshold가 None이면 항상 Ok. value >= 2*threshold → Crit, >= threshold → Warn.
    pub fn of(value: f64, threshold: Option<f64>) -> Self {
        match threshold {
            Some(t) if value >= t * 2.0 => WarnLevel::Crit,
            Some(t) if value >= t => WarnLevel::Warn,
            _ => WarnLevel::Ok,
        }
    }
}

/// 단계별 소요 시간 (밀리초). 해당 단계가 없으면 None (예: IP 직결 시 dns, http 시 tls).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PhaseTimings {
    pub dns_ms: Option<f64>,
    pub tcp_ms: f64,
    pub tls_ms: Option<f64>,
    /// 요청 전송 시작부터 응답 헤더 수신까지 (서버 처리 시간 근사).
    pub ttfb_ms: f64,
    /// 응답 바디 전체 수신에 걸린 시간.
    pub download_ms: f64,
    /// 이 hop의 전체 소요 시간 (위 단계들의 합과 거의 같음).
    pub total_ms: f64,
}

/// TLS 협상 결과.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    /// 예: "TLSv1.3"
    pub version: String,
    /// 예: "TLS13_AES_128_GCM_SHA256"
    pub cipher: String,
    /// ALPN 협상 결과: "h2" | "http/1.1" | None
    pub alpn: Option<String>,
    /// 협상된 키 교환 그룹, 예: "X25519" / "secp256r1"
    pub kx_group: Option<String>,
}

/// X.509 인증서 요약 (체인의 각 인증서마다 하나).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    /// subjectAltName 의 DNS/IP 항목들.
    pub san: Vec<String>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// 만료까지 남은 일수. 음수면 이미 만료됨.
    pub days_remaining: i64,
    /// 16진수 시리얼 (콜론 구분).
    pub serial: String,
    /// 서명 알고리즘, 예: "ECDSA-SHA256"
    pub sig_alg: String,
    /// 공개키 요약, 예: "RSA 2048" / "EC P-256"
    pub pubkey: String,
    pub is_ca: bool,
    /// SubjectPublicKeyInfo의 SHA-256 (소문자 hex). 키 핀/지문 비교용.
    /// 직렬화 키는 "spki_sha256". 역직렬화 시 누락되면 빈 문자열.
    #[serde(default)]
    pub spki_sha256: String,
    /// Authority Information Access의 caIssuers URL (있으면). leaf 인증서에서 파싱 시점에
    /// 추출해, --check-chain이 DER 재보유 없이 AIA 복구 가능성을 조회하는 데 쓴다.
    /// 직렬화 키는 "aia_ca_issuers". 역직렬화 시 누락되면 None.
    #[serde(default)]
    pub aia_ca_issuers: Option<String>,
}

/// 리다이렉트 체인의 한 hop (= 한 번의 연결 + 요청/응답).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopResult {
    pub url: String,
    /// 실제 연결에 사용한 IP.
    pub ip: IpAddr,
    pub port: u16,
    /// keep-alive 모드에서 기존 연결을 재사용한 hop이면 true
    /// (이때 dns/tls는 None, tcp_ms는 0.0).
    pub reused_conn: bool,
    /// 로컬 소켓 주소 (멀티 NIC/소스 IP 확인용).
    pub local_addr: Option<std::net::SocketAddr>,
    /// DNS가 반환한 모든 IP (필터링 후). resolve override 시 그 IP 하나.
    pub resolved_ips: Vec<IpAddr>,
    /// "HTTP/1.1" | "HTTP/2"
    pub http_version: String,
    pub status: u16,
    pub timings: PhaseTimings,
    /// https일 때만 Some.
    pub tls: Option<TlsInfo>,
    /// leaf 먼저, 서버가 보낸 순서대로.
    pub cert_chain: Vec<CertInfo>,
    pub response_headers: Vec<(String, String)>,
    pub body_bytes: u64,
    /// 3xx 응답의 Location (절대 URL로 해석된 값).
    pub redirect_to: Option<String>,
}

/// 프로브 실패가 발생한 단계.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorPhase {
    Setup,
    Dns,
    Tcp,
    Tls,
    Request,
    Download,
    Redirect,
}

impl std::fmt::Display for ErrorPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ErrorPhase::Setup => "setup",
            ErrorPhase::Dns => "dns",
            ErrorPhase::Tcp => "tcp",
            ErrorPhase::Tls => "tls",
            ErrorPhase::Request => "request",
            ErrorPhase::Download => "download",
            ErrorPhase::Redirect => "redirect",
        };
        f.write_str(s)
    }
}

/// 프로브 실패 정보.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeError {
    pub phase: ErrorPhase,
    pub message: String,
    /// 타임아웃으로 인한 실패 여부.
    pub timed_out: bool,
    /// 사람이 읽을 진단 힌트 + 한 줄 해법 (핸드셰이크 디코더 등이 채운다).
    /// 직렬화 키는 "hint". 역직렬화 시 누락되면 None.
    #[serde(default)]
    pub hint: Option<String>,
}

/// 프로브 1회의 결과. 실패하더라도 완료된 hop들은 hops에 보존된다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// 이 결과가 속한 대상 (ProbeConfig.url 문자열). 멀티 타깃 구분용.
    pub target: String,
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    pub hops: Vec<HopResult>,
    pub error: Option<ProbeError>,
    /// `--expect-*` 어설션 위반 사유 목록 (비어 있으면 통과).
    /// 네트워크 실패(error)와는 별개 — error가 있으면 어설션은 평가하지 않는다.
    pub expect_failures: Vec<String>,
    /// 프로브 시작부터 종료(성공/실패)까지의 실측 wall clock 시간.
    /// hop 사이의 리다이렉트 처리 시간도 포함하므로 hop total_ms 합과 정확히 같지는 않다.
    pub total_ms: f64,
}

impl ProbeResult {
    pub fn is_success(&self) -> bool {
        self.error.is_none()
    }

    /// 네트워크 성공 + 어설션 전체 통과.
    /// 계약(contract) API — 호출처는 is_success/expect_failures를 직접 쓰지만 유지.
    #[allow(dead_code)]
    pub fn is_pass(&self) -> bool {
        self.is_success() && self.expect_failures.is_empty()
    }

    /// 마지막(최종) hop. 리다이렉트가 없으면 첫 hop.
    pub fn final_hop(&self) -> Option<&HopResult> {
        self.hops.last()
    }

    /// 최종 hop의 HTTP 상태 코드.
    pub fn status(&self) -> Option<u16> {
        self.final_hop().map(|h| h.status)
    }

    /// 최종 https hop의 leaf 인증서.
    pub fn leaf_cert(&self) -> Option<&CertInfo> {
        self.hops.iter().rev().find_map(|h| h.cert_chain.first())
    }

    /// 단계별 시간을 모든 hop에 대해 합산한다 (리다이렉트 체인 통계용).
    pub fn summed_timings(&self) -> PhaseTimings {
        let mut sum = PhaseTimings::default();
        for hop in &self.hops {
            let t = &hop.timings;
            if let Some(d) = t.dns_ms {
                *sum.dns_ms.get_or_insert(0.0) += d;
            }
            sum.tcp_ms += t.tcp_ms;
            if let Some(d) = t.tls_ms {
                *sum.tls_ms.get_or_insert(0.0) += d;
            }
            sum.ttfb_ms += t.ttfb_ms;
            sum.download_ms += t.download_ms;
            sum.total_ms += t.total_ms;
        }
        sum
    }
}

// ===========================================================================
// v0.2 진단 확장용 공유 타입 (모두 ProbeResult 등에서 on-demand 계산; 저장 X)
// ===========================================================================

/// 서비스 건강 판정 상태. 색상/심각도 정렬에 사용.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictState {
    /// 모든 신호 정상.
    Pass,
    /// 일부 단계/어설션이 임계 초과 또는 경고 수준.
    Degraded,
    /// 네트워크 실패 등으로 서비스에 도달 불가.
    Down,
}

impl VerdictState {
    pub fn label(self) -> &'static str {
        match self {
            VerdictState::Pass => "PASS",
            VerdictState::Degraded => "DEGRADED",
            VerdictState::Down => "DOWN",
        }
    }
}

/// 한 프로브(또는 요약)에 대한 건강 판정. `verdict` 모듈이 생성한다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub state: VerdictState,
    /// 한 줄 헤드라인 (예: "TTFB p95 412ms (baseline 90ms, +358%)").
    pub headline: String,
    /// 판정을 뒷받침하는 근거들 (단계별 편차, 어설션 위반, cert 경고 등).
    pub reasons: Vec<String>,
}

/// 인증서 체인 분석 (완결성 + 최약 링크 만료 + AIA 복구 가능성).
/// `cert` 모듈이 `Vec<CertInfo>`(+선택적 AIA 네트워크 조회)로 생성한다.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainAnalysis {
    /// 서버가 leaf만 보내 체인이 끊겼는지 (중간 인증서 누락).
    pub incomplete: bool,
    /// AIA caIssuers로 체인을 재구성할 수 있는지 (--check-chain 시에만 Some).
    pub aia_repairable: Option<bool>,
    /// 체인 전체에서 가장 빨리 만료되는 인증서의 잔여 일수 (최약 링크).
    pub weakest_days: i64,
    /// 최약 링크 인증서의 subject CN (어느 cert가 먼저 죽는지).
    pub weakest_subject: String,
    /// 사람이 읽을 이슈 목록 ("intermediate missing", "root expires before leaf" 등).
    pub issues: Vec<String>,
}

/// 서비스 신원 지문 — 변경 탐지(⑤)용. 같은 호스트의 두 시점/두 엔드포인트 비교.
/// `diff` 모듈이 ProbeResult에서 추출한다.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Fingerprint {
    /// 최종 hop 연결 IP + DNS가 반환한 전체 IP 집합 (정렬된 문자열).
    pub resolved_ips: Vec<String>,
    pub connected_ip: Option<String>,
    pub http_version: Option<String>,
    pub status: Option<u16>,
    pub tls_version: Option<String>,
    pub alpn: Option<String>,
    /// leaf 인증서 시리얼.
    pub cert_serial: Option<String>,
    /// leaf SPKI SHA-256 (키 핀).
    pub cert_spki: Option<String>,
    /// leaf 만료일 (YYYY-MM-DD).
    pub cert_not_after: Option<String>,
    /// 식별성 있는 응답 헤더 일부 (server, content-type 등).
    pub headers: Vec<(String, String)>,
}

/// TLS 연결 보안 스코어카드 (--tls-grade). `tls_grade` 모듈이 협상된 TlsInfo +
/// 응답 헤더(HSTS) + 체인 분석(ChainAnalysis)으로 산출한다. 서버가 지원하는 모든
/// cipher를 전수 스캔하는 testssl과 달리, **실제 협상된 이 연결**의 구성을 등급화한다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsGrade {
    /// A~F 등급 글자 (A=최고).
    pub letter: char,
    /// 0~100 점수 (감점 합산 후, 0 하한).
    pub score: i32,
    /// 한 줄 요약 (예: "TLSv1.3, X25519, AEAD, HSTS 1y, chain OK").
    pub summary: String,
    /// 감점 사유 (예: "TLS 1.2 (not 1.3): -10"). 비어 있으면 만점.
    pub deductions: Vec<String>,
}

/// 캐시 적중 상태.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheStatus {
    Hit,
    Miss,
    /// 캐시 우회(동적 응답).
    Dynamic,
    /// 캐시 시그널 없음/판별 불가.
    Unknown,
}

/// CDN/캐시 효율 진단 (--cache-audit). `cache_audit` 모듈이 응답 헤더로 산출한다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheAudit {
    pub status: CacheStatus,
    /// CDN 종류 (예: "Cloudflare", "Fastly", "CloudFront", "Varnish").
    pub cdn: Option<String>,
    /// 캐시 edge/POP 식별자 (있으면).
    pub edge: Option<String>,
    /// Age 헤더 (초).
    pub age: Option<u64>,
    /// Cache-Control의 s-maxage 또는 max-age (초).
    pub max_age: Option<u64>,
    /// 한 줄 요약.
    pub summary: String,
    /// 캐시를 무력화/약화하는 안티패턴 (Set-Cookie, no-store, Vary:*, max-age=0 등).
    pub issues: Vec<String>,
}
