//! watch/alert: ping 모드에서 임계 초과(verdict != PASS) 시 webhook 발화 (--on-breach).
//!
//! httprove 자신은 시계열을 들지 않지만, 연속 실패/판정 악화를 즉석에서 감지해 webhook으로
//! 알리는 가벼운 알림이 풀 모니터링 스택을 세우기 전 임시 검증(카나리 관찰 등)에 유용하다.
//! 디바운스(`--breach-after`)와 쿨다운(`--cooldown`)으로 flapping을 억제한다. 발화는
//! fire-and-forget(tokio::spawn) — 프로브 루프를 막지 않는다. exec hook은 보안상 제외하고
//! webhook(외부 POST)만 지원한다.

use std::time::{Duration, Instant};

use serde_json::json;

use crate::types::{ProbeResult, VerdictState};

/// breach 평가 결과로 발화할 이벤트.
#[derive(Debug, PartialEq, Eq)]
pub enum Fire {
    None,
    Breach,
    Recover,
}

/// 타깃별 breach 추적 상태. record 순서대로 evaluate()를 호출한다.
#[derive(Default)]
pub struct BreachTracker {
    /// 연속 breach 횟수.
    consecutive: u32,
    /// 현재 breaching 중인지 (복구 감지용).
    breaching: bool,
    /// 마지막 발화 시각 (쿨다운 기준).
    last_fire: Option<Instant>,
}

impl BreachTracker {
    /// 한 프로브 결과를 평가해 발화 이벤트를 정한다.
    ///
    /// - `breached`: 이 결과가 임계 위반(verdict != PASS)인지.
    /// - `breach_after`: 연속 N회 위반부터 발화.
    /// - `cooldown`: 발화 후 이 시간 동안 재발화 억제.
    /// - `on_recover`: PASS로 복구 시 Recover 발화 여부.
    /// - `now`: 현재 시각(테스트 주입용).
    pub fn evaluate(
        &mut self,
        breached: bool,
        breach_after: u32,
        cooldown: Duration,
        on_recover: bool,
        now: Instant,
    ) -> Fire {
        if breached {
            self.consecutive += 1;
            self.breaching = true;
            if self.consecutive >= breach_after.max(1) {
                let cooled = self
                    .last_fire
                    .map(|t| now.duration_since(t) >= cooldown)
                    .unwrap_or(true);
                if cooled {
                    self.last_fire = Some(now);
                    return Fire::Breach;
                }
            }
            Fire::None
        } else {
            let was = self.breaching;
            self.breaching = false;
            self.consecutive = 0;
            if was && on_recover {
                Fire::Recover
            } else {
                Fire::None
            }
        }
    }
}

/// 알림 JSON 페이로드를 만든다.
pub fn payload(event: &str, result: &ProbeResult, state: VerdictState, headline: &str) -> Vec<u8> {
    json!({
        "event": event,
        "target": result.target,
        "seq": result.seq,
        "state": state.label(),
        "headline": headline,
        "timestamp": result.timestamp.to_rfc3339(),
    })
    .to_string()
    .into_bytes()
}

/// webhook을 fire-and-forget으로 POST한다(프로브 루프를 막지 않음). 실패는 stderr 경고만.
pub fn fire(url: String, payload: Vec<u8>) {
    tokio::spawn(async move {
        if let Err(e) = crate::otlp::post_json(&url, payload).await {
            eprintln!("httprove: webhook to {url} failed: {e}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_on_first_breach_then_respects_cooldown() {
        let mut b = BreachTracker::default();
        let t0 = Instant::now();
        let cd = Duration::from_secs(60);
        assert_eq!(b.evaluate(true, 1, cd, false, t0), Fire::Breach);
        // 쿨다운 내 재breach → 억제.
        assert_eq!(
            b.evaluate(true, 1, cd, false, t0 + Duration::from_secs(10)),
            Fire::None
        );
        // 쿨다운 경과 → 재발화.
        assert_eq!(
            b.evaluate(true, 1, cd, false, t0 + Duration::from_secs(61)),
            Fire::Breach
        );
    }

    #[test]
    fn waits_for_breach_after_threshold() {
        let mut b = BreachTracker::default();
        let t = Instant::now();
        let cd = Duration::from_secs(60);
        assert_eq!(b.evaluate(true, 3, cd, false, t), Fire::None); // 1
        assert_eq!(b.evaluate(true, 3, cd, false, t), Fire::None); // 2
        assert_eq!(b.evaluate(true, 3, cd, false, t), Fire::Breach); // 3
    }

    #[test]
    fn recover_fires_only_once_when_enabled() {
        let mut b = BreachTracker::default();
        let t = Instant::now();
        let cd = Duration::from_secs(60);
        b.evaluate(true, 1, cd, true, t); // breaching
        assert_eq!(b.evaluate(false, 1, cd, true, t), Fire::Recover);
        // 이미 복구됨 → 추가 발화 없음.
        assert_eq!(b.evaluate(false, 1, cd, true, t), Fire::None);
    }

    #[test]
    fn no_recover_when_disabled() {
        let mut b = BreachTracker::default();
        let t = Instant::now();
        let cd = Duration::from_secs(60);
        b.evaluate(true, 1, cd, false, t);
        assert_eq!(b.evaluate(false, 1, cd, false, t), Fire::None);
    }
}
