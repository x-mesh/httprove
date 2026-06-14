//! 캡처 트랩(capture trap) + 세션 record/replay.
//!
//! 담당 기능:
//! - ㉝ 캡처 트랩: 실패가 처음 관측될 때까지 반복 프로브하고, 직전까지의 결과 + 실패 결과를
//!   파일로 저장한다(나중에 사후 분석). **트랩 루프 로직 자체는 lib.rs가 보유**하고,
//!   여기서는 save_session(직렬화)만 제공한다.
//! - ㉞ record/replay: 기록한 세션을 다시 렌더링한다.
//!
//! ## save_session(results, path) -> Result<()>
//! results(여러 ProbeResult)를 파일로 직렬화한다.
//! - 포맷: JSON 배열 또는 JSON Lines(NDJSON) — 둘 중 하나로 일관되게.
//!   메타(예: 저장 시각, 도구 버전, 개수)를 포함하려면 `{"meta":{...},"results":[...]}`
//!   래퍼 형태를 권장한다. run_replay와 **반드시 호환**되게 작성한다.
//! - ProbeResult는 Serialize 가능하므로 serde_json으로 바로 직렬화.
//! - 파일 IO 오류는 anyhow context로 감싼다.
//!
//! ## run_replay(path, color) -> ExitCode
//! 기록 파일을 읽어 각 ProbeResult를 `crate::output::text::print_single(&r, &cfg)`로
//! 다시 렌더링한다(여러 개면 블록 사이 빈 줄).
//! - OutputConfig는 합리적 기본값으로 구성: color는 인자, verbose=false,
//!   cert_warn_days=30, warn=Default, show_target=(결과가 2건 이상 또는 타깃이 여러 종류).
//! - 파일 없음/파싱 실패면 에러 출력 후 ExitCode::from(1).
//! - 렌더 자체는 정보 제공이므로 성공 시 ExitCode::SUCCESS
//!   (기록된 결과의 성공/실패와 무관하게 0).
//!
//! ## 구현 메모
//! - 패닉 금지. 모든 fallible 경로는 Result/Option.
//! - save_session/run_replay의 포맷은 서로 짝이 맞아야 한다(라운드트립 가능).
//! - #[cfg(test)]로 save_session→파싱 라운드트립을 검증하면 좋다(tempfile 없이 직렬화
//!   문자열만 비교해도 됨).

use std::process::ExitCode;

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::output::OutputConfig;
use crate::types::{ProbeResult, WarnThresholds};

/// 도구 이름 (메타 기록용). 역직렬화 시 누락되면 빈 문자열.
const TOOL_NAME: &str = "httprove";
/// replay 시 인증서 만료 경고 기본 임계값 (일).
const REPLAY_CERT_WARN_DAYS: i64 = 30;

/// 세션 파일 메타: 어떤 도구/버전이 언제 기록했는지.
/// 역직렬화 시 모든 필드가 선택적이라 형식이 약간 달라도 results만 있으면 읽힌다.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionMeta {
    /// 기록 도구 이름 ("httprove").
    #[serde(default)]
    tool: String,
    /// 기록 시점의 도구 버전 (CARGO_PKG_VERSION).
    #[serde(default)]
    version: String,
    /// 세션을 파일로 저장한 시각 (UTC).
    recorded_at: DateTime<Utc>,
}

/// 세션 파일 전체: 메타 + 기록된 프로브 결과들.
/// `{"meta":{...},"results":[...]}` 래퍼로 직렬화한다.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Session {
    meta: SessionMeta,
    results: Vec<ProbeResult>,
}

/// 여러 ProbeResult를 파일로 직렬화한다 (run_replay와 호환되는 포맷).
pub fn save_session(results: &[ProbeResult], path: &str) -> anyhow::Result<()> {
    let session = Session {
        meta: SessionMeta {
            tool: TOOL_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            recorded_at: Utc::now(),
        },
        // 소유권만 빌려 직렬화하면 되지만 Session은 소유 Vec을 요구하므로 복제한다.
        results: results.to_vec(),
    };

    // pretty JSON + 끝 개행 (다른 산출물과 동일한 관례).
    let mut json =
        serde_json::to_string_pretty(&session).context("failed to serialize session to JSON")?;
    json.push('\n');
    std::fs::write(path, json).with_context(|| format!("failed to write session file {path}"))?;
    Ok(())
}

/// 기록 파일을 읽어 Session으로 파싱한다. 파일 IO/파싱 오류는 anyhow context로 감싼다.
fn load_session(path: &str) -> anyhow::Result<Session> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read session file {path}"))?;
    let session: Session = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse session file {path}"))?;
    Ok(session)
}

/// 기록된 세션을 읽어 각 결과를 print_single로 다시 렌더링한다.
pub fn run_replay(path: &str, color: bool) -> ExitCode {
    let session = match load_session(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("httprove: {e:#}");
            return ExitCode::from(1);
        }
    };

    // show_target: 결과가 2건 이상이거나 타깃이 여러 종류면 각 블록에 타깃을 밝힌다.
    let multiple_targets = session
        .results
        .iter()
        .skip(1)
        .any(|r| r.target != session.results[0].target);
    let show_target = session.results.len() >= 2 || multiple_targets;

    let cfg = OutputConfig {
        color,
        verbose: false,
        cert_warn_days: REPLAY_CERT_WARN_DAYS,
        warn: WarnThresholds::default(),
        show_target,
    };

    // 여러 결과면 블록 사이에 빈 줄을 넣어 가독성을 확보한다.
    for (i, result) in session.results.iter().enumerate() {
        if i > 0 {
            println!();
        }
        crate::output::text::print_single(result, &cfg);
    }

    // 렌더는 정보 제공이므로 기록된 성공/실패와 무관하게 항상 0.
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    use chrono::Utc;

    use super::*;
    use crate::types::{ErrorPhase, HopResult, PhaseTimings, ProbeError};

    /// 성공 프로브 생성 헬퍼 (http 대상: dns/tls 단계 없음).
    fn ok_probe(target: &str, seq: u64) -> ProbeResult {
        ProbeResult {
            target: target.to_string(),
            seq,
            timestamp: Utc::now(),
            hops: vec![HopResult {
                url: target.to_string(),
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 80,
                reused_conn: false,
                local_addr: None,
                resolved_ips: vec![],
                http_version: "HTTP/1.1".to_string(),
                status: 200,
                timings: PhaseTimings {
                    dns_ms: None,
                    tcp_ms: 2.0,
                    tls_ms: None,
                    ttfb_ms: 4.0,
                    download_ms: 5.0,
                    total_ms: 11.0,
                },
                tls: None,
                cert_chain: vec![],
                response_headers: vec![],
                body_bytes: 0,
                redirect_to: None,
            }],
            error: None,
            expect_failures: vec![],
            total_ms: 11.0,
        }
    }

    /// 실패 프로브 생성 헬퍼 (hop 없이 tcp 단계에서 실패).
    fn err_probe(target: &str, seq: u64) -> ProbeResult {
        ProbeResult {
            target: target.to_string(),
            seq,
            timestamp: Utc::now(),
            hops: vec![],
            error: Some(ProbeError {
                phase: ErrorPhase::Tcp,
                message: "connection refused".to_string(),
                timed_out: false,
                hint: None,
            }),
            expect_failures: vec![],
            total_ms: 3.0,
        }
    }

    /// 충돌 없는 임시 파일 경로 (pid + 나노초 시각).
    fn temp_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "httprove-session-{tag}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    #[test]
    fn save_then_load_roundtrip() {
        let results = vec![
            ok_probe("http://a.example/", 0),
            err_probe("http://a.example/", 1),
        ];

        let path = temp_path("roundtrip");
        let path_str = path.to_string_lossy().into_owned();

        save_session(&results, &path_str).unwrap();
        let loaded = load_session(&path_str);
        let _ = std::fs::remove_file(&path);
        let loaded = loaded.unwrap();

        // 메타는 도구/버전이 채워져 있어야 한다.
        assert_eq!(loaded.meta.tool, "httprove");
        assert_eq!(loaded.meta.version, env!("CARGO_PKG_VERSION"));

        // 결과 개수/순서/핵심 필드가 보존되어야 한다.
        assert_eq!(loaded.results.len(), 2);
        assert_eq!(loaded.results[0].seq, 0);
        assert_eq!(loaded.results[0].target, "http://a.example/");
        assert_eq!(loaded.results[0].status(), Some(200));
        assert!(loaded.results[0].is_success());

        assert_eq!(loaded.results[1].seq, 1);
        assert!(!loaded.results[1].is_success());
        let err = loaded.results[1].error.as_ref().unwrap();
        assert_eq!(err.phase, ErrorPhase::Tcp);
        assert_eq!(err.message, "connection refused");
    }

    #[test]
    fn replay_missing_file_is_error() {
        let path = temp_path("missing");
        let path_str = path.to_string_lossy().into_owned();
        // 존재하지 않는 경로 → ExitCode::from(1).
        assert_eq!(run_replay(&path_str, false), ExitCode::from(1));
    }

    #[test]
    fn replay_existing_session_succeeds() {
        let results = vec![ok_probe("http://a.example/", 0)];
        let path = temp_path("replay-ok");
        let path_str = path.to_string_lossy().into_owned();
        save_session(&results, &path_str).unwrap();

        let code = run_replay(&path_str, false);
        let _ = std::fs::remove_file(&path);
        // 기록된 결과의 성공/실패와 무관하게 렌더 성공이면 0.
        assert_eq!(code, ExitCode::SUCCESS);
    }
}
