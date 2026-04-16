//! モジュール実行統計
//!
//! 各モジュールのスキャン実行時間、検知イベント数、初期スキャン結果を集計する。
//! MetricsCollector が全体統計を扱うのに対し、こちらはモジュール単位の粒度で集計し、
//! パフォーマンスボトルネックや不調モジュールの特定を支援する。

use crate::config::ModuleStatsConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

/// モジュール単位の統計情報
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleStats {
    /// モジュール名
    pub module: String,
    /// 検知された SecurityEvent の総数
    pub events_total: u64,
    /// INFO レベルの検知数
    pub events_info: u64,
    /// WARNING レベルの検知数
    pub events_warning: u64,
    /// CRITICAL レベルの検知数
    pub events_critical: u64,
    /// 直近の検知イベントのタイムスタンプ（RFC3339 UTC）
    pub last_event_at: Option<String>,
    /// 起動時スキャンの実行時間（ミリ秒）
    pub initial_scan_duration_ms: Option<u64>,
    /// 起動時スキャンでのアイテム数
    pub initial_scan_items_scanned: Option<usize>,
    /// 起動時スキャンで検知された問題数
    pub initial_scan_issues_found: Option<usize>,
    /// 起動時スキャンのサマリーメッセージ
    pub initial_scan_summary: Option<String>,
    /// 起動時スキャンを実行した時刻（RFC3339 UTC）
    pub initial_scan_at: Option<String>,
}

/// モジュール統計レジストリ
///
/// 内部に `Arc<RwLock<HashMap<String, ModuleStats>>>` を持ち、Clone 可能なハンドルとして共有する。
#[derive(Clone, Default)]
pub struct ModuleStatsHandle {
    inner: Arc<StdRwLock<HashMap<String, ModuleStats>>>,
}

impl ModuleStatsHandle {
    /// 空のハンドルを作成する
    pub fn new() -> Self {
        Self::default()
    }

    /// モジュール名を事前登録する（未検知でも一覧に現れるようにする）
    pub fn ensure(&self, module: &str) {
        // unwrap safety: RwLock が poisoned になるのはパニック時のみ
        let mut guard = self.inner.write().unwrap();
        guard
            .entry(module.to_string())
            .or_insert_with(|| ModuleStats {
                module: module.to_string(),
                ..Default::default()
            });
    }

    /// 複数のモジュール名を一度に登録する
    pub fn ensure_all<I, S>(&self, modules: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        // unwrap safety: RwLock が poisoned になるのはパニック時のみ
        let mut guard = self.inner.write().unwrap();
        for m in modules {
            let name = m.as_ref();
            guard
                .entry(name.to_string())
                .or_insert_with(|| ModuleStats {
                    module: name.to_string(),
                    ..Default::default()
                });
        }
    }

    /// 起動時スキャン結果を記録する
    pub fn record_initial_scan(
        &self,
        module: &str,
        duration: Duration,
        items: usize,
        issues: usize,
        summary: &str,
    ) {
        // unwrap safety: RwLock が poisoned になるのはパニック時のみ
        let mut guard = self.inner.write().unwrap();
        let entry = guard
            .entry(module.to_string())
            .or_insert_with(|| ModuleStats {
                module: module.to_string(),
                ..Default::default()
            });
        entry.initial_scan_duration_ms = Some(duration.as_millis() as u64);
        entry.initial_scan_items_scanned = Some(items);
        entry.initial_scan_issues_found = Some(issues);
        entry.initial_scan_summary = Some(summary.to_string());
        entry.initial_scan_at = Some(current_rfc3339());
    }

    /// SecurityEvent を記録する（source_module 別の集計）
    pub fn record_event(&self, event: &SecurityEvent) {
        // unwrap safety: RwLock が poisoned になるのはパニック時のみ
        let mut guard = self.inner.write().unwrap();
        let entry = guard
            .entry(event.source_module.clone())
            .or_insert_with(|| ModuleStats {
                module: event.source_module.clone(),
                ..Default::default()
            });
        entry.events_total = entry.events_total.saturating_add(1);
        match event.severity {
            Severity::Info => entry.events_info = entry.events_info.saturating_add(1),
            Severity::Warning => entry.events_warning = entry.events_warning.saturating_add(1),
            Severity::Critical => entry.events_critical = entry.events_critical.saturating_add(1),
        }
        entry.last_event_at = Some(current_rfc3339());
    }

    /// 指定モジュールの統計を取得する
    pub fn get(&self, module: &str) -> Option<ModuleStats> {
        // unwrap safety: RwLock が poisoned になるのはパニック時のみ
        let guard = self.inner.read().unwrap();
        guard.get(module).cloned()
    }

    /// 全モジュールの統計をモジュール名でソートして返す
    pub fn snapshot(&self) -> Vec<ModuleStats> {
        // unwrap safety: RwLock が poisoned になるのはパニック時のみ
        let guard = self.inner.read().unwrap();
        let mut list: Vec<ModuleStats> = guard.values().cloned().collect();
        list.sort_by(|a, b| a.module.cmp(&b.module));
        list
    }
}

/// 現在時刻を RFC3339 形式の文字列で返す（UTC 秒精度）
fn current_rfc3339() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    format_rfc3339_utc(secs)
}

/// エポック秒を RFC3339 UTC 形式に変換する（外部依存なしの最小実装）
fn format_rfc3339_utc(epoch_secs: i64) -> String {
    const SECS_PER_DAY: i64 = 86_400;
    let days = epoch_secs.div_euclid(SECS_PER_DAY);
    let time_of_day = epoch_secs.rem_euclid(SECS_PER_DAY);
    let hour = (time_of_day / 3600) as u32;
    let minute = ((time_of_day % 3600) / 60) as u32;
    let second = (time_of_day % 60) as u32;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

/// 1970-01-01 からの経過日数をカレンダー日付に変換する（Howard Hinnant's algorithm）
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

/// EventBus サブスクライバーとして統計を集計するタスクを spawn する
pub fn spawn_event_subscriber(handle: ModuleStatsHandle, bus: &EventBus) {
    let mut receiver = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Ok(event) => handle.record_event(&event),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        skipped = n,
                        "モジュール統計: {} 件のイベントをスキップ（遅延）",
                        n
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!(
                        "イベントバスが閉じられました。モジュール統計サブスクライバーを終了します"
                    );
                    break;
                }
            }
        }
    });
}

/// 統計サマリーを定期的にログ出力するタスクを spawn する
///
/// `log_interval_secs` が 0 の場合は何もしない。
pub fn spawn_summary_logger(handle: ModuleStatsHandle, config: &ModuleStatsConfig) {
    if config.log_interval_secs == 0 {
        return;
    }
    let interval = Duration::from_secs(config.log_interval_secs);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // 最初の即時 tick をスキップ
        loop {
            ticker.tick().await;
            emit_summary(&handle);
        }
    });
}

fn emit_summary(handle: &ModuleStatsHandle) {
    let stats = handle.snapshot();
    if stats.is_empty() {
        return;
    }

    let active: Vec<&ModuleStats> = stats.iter().filter(|s| s.events_total > 0).collect();
    let total_events: u64 = stats.iter().map(|s| s.events_total).sum();
    let active_modules = active.len();
    let total_modules = stats.len();

    tracing::info!(
        total_modules = total_modules,
        active_modules = active_modules,
        total_events = total_events,
        "[ModuleStatsSummary] 全モジュール: {}, 検知ありモジュール: {}, 合計イベント: {}",
        total_modules,
        active_modules,
        total_events
    );

    if !active.is_empty() {
        let counts: Vec<String> = active
            .iter()
            .map(|s| {
                format!(
                    "{}={}(I:{},W:{},C:{})",
                    s.module, s.events_total, s.events_info, s.events_warning, s.events_critical
                )
            })
            .collect();
        tracing::info!(
            modules = %counts.join(", "),
            "[ModuleStatsSummary] モジュール別検知数"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_ensure_and_snapshot() {
        let handle = ModuleStatsHandle::new();
        handle.ensure("file_integrity");
        handle.ensure("process_monitor");
        handle.ensure("file_integrity"); // duplicate is a no-op

        let snap = handle.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].module, "file_integrity");
        assert_eq!(snap[1].module, "process_monitor");
        assert_eq!(snap[0].events_total, 0);
    }

    #[test]
    fn test_ensure_all() {
        let handle = ModuleStatsHandle::new();
        handle.ensure_all(["a", "b", "c"]);
        let snap = handle.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].module, "a");
        assert_eq!(snap[2].module, "c");
    }

    #[test]
    fn test_record_event_counts_by_severity() {
        let handle = ModuleStatsHandle::new();
        handle.record_event(&SecurityEvent::new(
            "t",
            Severity::Info,
            "mod_a",
            "info msg",
        ));
        handle.record_event(&SecurityEvent::new(
            "t",
            Severity::Warning,
            "mod_a",
            "warn msg",
        ));
        handle.record_event(&SecurityEvent::new(
            "t",
            Severity::Critical,
            "mod_a",
            "crit msg",
        ));
        handle.record_event(&SecurityEvent::new(
            "t",
            Severity::Warning,
            "mod_b",
            "warn msg",
        ));

        let a = handle.get("mod_a").expect("mod_a");
        assert_eq!(a.events_total, 3);
        assert_eq!(a.events_info, 1);
        assert_eq!(a.events_warning, 1);
        assert_eq!(a.events_critical, 1);
        assert!(a.last_event_at.is_some());

        let b = handle.get("mod_b").expect("mod_b");
        assert_eq!(b.events_total, 1);
        assert_eq!(b.events_warning, 1);
    }

    #[test]
    fn test_record_initial_scan() {
        let handle = ModuleStatsHandle::new();
        handle.record_initial_scan(
            "file_integrity",
            Duration::from_millis(1234),
            500,
            3,
            "500 ファイル, 3 問題",
        );
        let s = handle.get("file_integrity").expect("file_integrity");
        assert_eq!(s.initial_scan_duration_ms, Some(1234));
        assert_eq!(s.initial_scan_items_scanned, Some(500));
        assert_eq!(s.initial_scan_issues_found, Some(3));
        assert_eq!(
            s.initial_scan_summary.as_deref(),
            Some("500 ファイル, 3 問題")
        );
        assert!(s.initial_scan_at.is_some());
    }

    #[test]
    fn test_snapshot_sorted() {
        let handle = ModuleStatsHandle::new();
        handle.ensure("zeta");
        handle.ensure("alpha");
        handle.ensure("mid");
        let snap = handle.snapshot();
        assert_eq!(snap[0].module, "alpha");
        assert_eq!(snap[1].module, "mid");
        assert_eq!(snap[2].module, "zeta");
    }

    #[test]
    fn test_get_missing_returns_none() {
        let handle = ModuleStatsHandle::new();
        assert!(handle.get("unknown").is_none());
    }

    #[test]
    fn test_concurrent_record_event() {
        let handle = ModuleStatsHandle::new();
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let h = handle.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        h.record_event(&SecurityEvent::new("t", Severity::Info, "mod", "msg"));
                    }
                })
            })
            .collect();
        for t in handles {
            t.join().unwrap();
        }
        let s = handle.get("mod").expect("mod");
        assert_eq!(s.events_total, 1000);
        assert_eq!(s.events_info, 1000);
    }

    #[tokio::test]
    async fn test_spawn_event_subscriber() {
        let bus = EventBus::new(16);
        let handle = ModuleStatsHandle::new();
        spawn_event_subscriber(handle.clone(), &bus);

        bus.publish(SecurityEvent::new("t", Severity::Info, "sub_mod", "test"));
        bus.publish(SecurityEvent::new(
            "t",
            Severity::Critical,
            "sub_mod",
            "test",
        ));

        tokio::time::sleep(Duration::from_millis(100)).await;

        let s = handle.get("sub_mod").expect("sub_mod");
        assert_eq!(s.events_total, 2);
        assert_eq!(s.events_info, 1);
        assert_eq!(s.events_critical, 1);
    }

    #[test]
    fn test_format_rfc3339_utc_epoch() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn test_serialize_stats_json() {
        let handle = ModuleStatsHandle::new();
        handle.ensure("mod_a");
        handle.record_event(&SecurityEvent::new("t", Severity::Warning, "mod_a", "msg"));
        let s = handle.get("mod_a").expect("mod_a");
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"module\":\"mod_a\""));
        assert!(json.contains("\"events_total\":1"));
        assert!(json.contains("\"events_warning\":1"));
    }

    #[tokio::test]
    async fn test_spawn_summary_logger_disabled_when_zero() {
        let handle = ModuleStatsHandle::new();
        // log_interval_secs = 0 のとき何も spawn しないことを確認（パニックしない）
        let config = ModuleStatsConfig {
            enabled: true,
            log_interval_secs: 0,
        };
        spawn_summary_logger(handle, &config);
    }
}
