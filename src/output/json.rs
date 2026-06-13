//! JSON 출력 (스크립트/모니터링 연동용).
//!
//! - `probe_json`: ProbeResult를 `{"type":"probe", ...ProbeResult 필드...}` 형태의
//!   한 줄 JSON으로 직렬화한다 (NDJSON 친화적, 줄바꿈 미포함).
//! - `summary_json`: `{"type":"summary","target":...,"sent":N,"ok":N,"failed":N,
//!   "expect_failed":N,"loss_pct":F,"phases":{"dns":{PhaseStats...},...},
//!   "status_counts":{"200":9}}` 샘플 없는 단계는 phases에서 생략.
//!
//! serde_json::json! 매크로와 types/stats의 Serialize 구현을 활용하면 된다.

use serde_json::{Map, Value, json};

use crate::stats::{Phase, StatsCollector};
use crate::types::ProbeResult;

/// 프로브 1건 → 한 줄 JSON (개행 미포함).
pub fn probe_json(result: &ProbeResult) -> String {
    // ProbeResult 직렬화 + "type":"probe" 병합. 직렬화 실패(이론상 NaN 등)는
    // unwrap 대신 에러 객체로 폴백해 NDJSON 스트림이 깨지지 않게 한다.
    let value = match serde_json::to_value(result) {
        Ok(Value::Object(fields)) => {
            let mut map = Map::new();
            map.insert("type".to_string(), Value::String("probe".to_string()));
            map.extend(fields);
            Value::Object(map)
        }
        // 구조체 직렬화 결과는 항상 객체지만, 방어적으로 처리.
        Ok(other) => json!({ "type": "probe", "value": other }),
        Err(e) => json!({
            "type": "probe",
            "seq": result.seq,
            "serialize_error": e.to_string(),
        }),
    };
    value.to_string()
}

/// 누적 통계 → 한 줄 JSON (개행 미포함).
pub fn summary_json(target: &str, stats: &StatsCollector) -> String {
    // 샘플 있는 단계만 phases에 포함.
    let mut phases = Map::new();
    for phase in Phase::ALL {
        let Some(ps) = stats.phase_stats(phase) else {
            continue;
        };
        if let Ok(v) = serde_json::to_value(ps) {
            phases.insert(phase.label().to_string(), v);
        }
        // 직렬화 불가(이론상 NaN)면 해당 단계 생략.
    }

    // u16 키를 문자열 키로 변환 ({"200":9} 형태).
    let mut status_counts = Map::new();
    for (code, n) in stats.status_counts() {
        status_counts.insert(code.to_string(), Value::from(*n));
    }

    // json! 매크로는 내부에서 to_value().unwrap()을 쓰므로 f64는 유한값 보장.
    let loss = stats.loss_pct();
    let loss = if loss.is_finite() { loss } else { 0.0 };

    json!({
        "type": "summary",
        "target": target,
        "sent": stats.sent(),
        "ok": stats.succeeded(),
        "failed": stats.failed(),
        "expect_failed": stats.expect_failed(),
        "loss_pct": loss,
        "phases": phases,
        "status_counts": status_counts,
    })
    .to_string()
}
