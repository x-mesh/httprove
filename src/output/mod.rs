//! CLI 출력 (텍스트 / JSON / Prometheus / 베이스라인).

pub mod baseline;
pub mod json;
pub mod prom;
pub mod text;

use crate::types::WarnThresholds;

/// 텍스트 출력 옵션.
#[derive(Debug, Clone, Copy)]
pub struct OutputConfig {
    /// false면 ANSI 색상 없이 출력 (main에서 tty/--no-color 판단).
    pub color: bool,
    /// 단발 모드에서 응답 헤더까지 출력.
    pub verbose: bool,
    /// 인증서 만료 경고 임계값 (일).
    pub cert_warn_days: i64,
    /// `--warn <phase>=<ms>` 임계값 (초과 단계를 노랑/빨강 강조).
    pub warn: WarnThresholds,
    /// 멀티 타깃 모드: ping 라인 앞에 타깃 표시.
    pub show_target: bool,
}
