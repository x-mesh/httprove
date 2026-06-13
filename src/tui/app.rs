//! TUI 앱 상태 (렌더링과 분리, 멀티 타깃).
//!
//! - 타깃별 상태(TargetState): 이름, StatsCollector, 마지막 성공 결과
//! - tab 키로 순환하는 선택 타깃 인덱스 (헤더/워터폴/통계 표시 대상)
//! - 전체 타깃 병합 히스토리 (최근 HISTORY_CAP개, 차트 + 하단 히스토리 패널용)
//! - paused / finished 플래그, --warn 임계값
//!
//! `update(&mut self, result: ProbeResult)`로 결과를 타깃별로 라우팅하고,
//! `reset(&mut self)`로 r 키(전체 초기화)를, `next_target`으로 tab 키를 처리한다.

use std::collections::{HashMap, VecDeque};

use crate::stats::StatsCollector;
use crate::types::{ProbeResult, WarnThresholds};

/// 차트/히스토리용 병합 결과 히스토리 최대 보존 개수.
pub const HISTORY_CAP: usize = 512;

/// 타깃 하나의 수집 상태.
pub struct TargetState {
    /// 대상 URL 전체 문자열 (ProbeConfig.url 직렬화 == ProbeResult.target).
    pub name: String,
    /// 짧은 호스트 라벨: host[:port] (차트 범례/히스토리 prefix/패널 제목용).
    pub short: String,
    /// 이 타깃의 누적 통계 (CLI ping 모드와 공용 수집기).
    pub stats: StatsCollector,
    /// 이 타깃의 마지막 성공 프로브 (헤더/워터폴/인증서 표시용).
    pub last_success: Option<ProbeResult>,
}

/// TUI 전체 상태. 렌더링(ui.rs)은 이 구조체를 읽기만 한다.
pub struct App {
    /// 입력 순서를 보존한 타깃 목록.
    pub targets: Vec<TargetState>,
    /// ProbeResult.target → targets 인덱스 (결과 라우팅용).
    index: HashMap<String, usize>,
    /// tab 키로 순환하는 선택 타깃 인덱스.
    pub selected: usize,
    /// 인증서 만료 경고 임계 일수.
    pub cert_warn_days: i64,
    /// `--warn` 임계값 (워터폴 ms 값 노랑/빨강 강조).
    pub warn: WarnThresholds,
    /// 전체 타깃 병합 히스토리 (성공/실패 모두 보존, 차트는 성공만 사용).
    pub history: VecDeque<ProbeResult>,
    /// space 키로 토글되는 일시정지 상태 (runner의 paused 플래그와 동기화).
    pub paused: bool,
    /// 모든 타깃의 count 소진으로 프로브 루프가 끝났는지 여부.
    pub finished: bool,
}

impl App {
    /// names는 ProbeConfig.url.to_string() 순서 그대로 (runner의 타깃 순서와 동일).
    pub fn new(names: Vec<String>, cert_warn_days: i64, warn: WarnThresholds) -> Self {
        let targets: Vec<TargetState> = names
            .into_iter()
            .map(|name| TargetState {
                short: short_host_label(&name),
                name,
                stats: StatsCollector::new(),
                last_success: None,
            })
            .collect();
        let index: HashMap<String, usize> = targets
            .iter()
            .enumerate()
            .map(|(i, t)| (t.name.clone(), i))
            .collect();
        Self {
            targets,
            index,
            selected: 0,
            cert_warn_days,
            warn,
            history: VecDeque::with_capacity(HISTORY_CAP),
            paused: false,
            finished: false,
        }
    }

    /// 현재 선택된 타깃. cli가 타깃 1개 이상을 보장하지만 방어적으로 Option.
    pub fn selected_target(&self) -> Option<&TargetState> {
        self.targets.get(self.selected)
    }

    /// ProbeResult.target 문자열에 해당하는 타깃 인덱스.
    pub fn target_index(&self, target: &str) -> Option<usize> {
        self.index.get(target).copied()
    }

    /// ProbeResult.target의 짧은 호스트 라벨 (히스토리 prefix용).
    pub fn short_label(&self, target: &str) -> Option<&str> {
        self.target_index(target)
            .and_then(|i| self.targets.get(i))
            .map(|t| t.short.as_str())
    }

    /// 프로브 결과 1건을 해당 타깃 상태와 병합 히스토리에 반영한다.
    pub fn update(&mut self, result: ProbeResult) {
        if let Some(&i) = self.index.get(&result.target)
            && let Some(target) = self.targets.get_mut(i)
        {
            target.stats.record(&result);
            if result.is_success() {
                target.last_success = Some(result.clone());
            }
        }
        self.history.push_back(result);
        while self.history.len() > HISTORY_CAP {
            self.history.pop_front();
        }
    }

    /// tab 키: 다음 타깃 선택 (타깃 1개면 no-op).
    pub fn next_target(&mut self) {
        if self.targets.len() > 1 {
            self.selected = (self.selected + 1) % self.targets.len();
        }
    }

    /// r 키: 모든 타깃의 통계/마지막 성공과 병합 히스토리를 초기화한다
    /// (selected/paused/finished는 유지).
    pub fn reset(&mut self) {
        for target in &mut self.targets {
            target.stats.reset();
            target.last_success = None;
        }
        self.history.clear();
    }

    /// rx가 닫혔을 때(모든 타깃 count 소진) finished로 전환한다.
    pub fn finish(&mut self) {
        self.finished = true;
    }

    /// 전체 타깃 합산 sent (히스토리 패널 제목용).
    pub fn total_sent(&self) -> u64 {
        self.targets.iter().map(|t| t.stats.sent()).sum()
    }
}

/// 타깃 URL 문자열에서 짧은 라벨을 만든다: host[:port].
/// url 크레이트는 스킴 기본 포트를 정규화로 제거하므로 port()가 Some이면 비기본 포트.
/// 파싱 실패 시 원문을 그대로 반환한다 (방어적 — cli가 유효 URL을 보장).
pub fn short_host_label(target: &str) -> String {
    match url::Url::parse(target) {
        Ok(u) => {
            let host = u.host_str().unwrap_or(target);
            match u.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            }
        }
        Err(_) => target.to_string(),
    }
}
