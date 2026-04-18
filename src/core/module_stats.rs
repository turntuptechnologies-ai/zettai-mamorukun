//! モジュール実行統計
//!
//! 各モジュールのスキャン実行時間、検知イベント数、初期スキャン結果を集計する。
//! MetricsCollector が全体統計を扱うのに対し、こちらはモジュール単位の粒度で集計し、
//! パフォーマンスボトルネックや不調モジュールの特定を支援する。

use crate::config::ModuleStatsConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

/// スキャン実行時間ヒストグラムに保持するサンプル数の上限（リングバッファ）
///
/// 百分位点（P50/P95/P99）はこのバッファ内のサンプルから計算される。
/// 上限に達すると最古のサンプルが破棄される。
pub const SCAN_HISTOGRAM_CAPACITY: usize = 1024;

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
    /// スキャン実行回数（ヒストグラムのサンプル総数。バッファ上限を超過した累積数）
    #[serde(default)]
    pub scan_count: u64,
    /// スキャン実行時間の累積（ミリ秒）。Prometheus の `_sum` 系列で利用
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_total_ms: Option<u64>,
    /// リングバッファ内の最小スキャン時間（ミリ秒）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_min_ms: Option<u64>,
    /// リングバッファ内の最大スキャン時間（ミリ秒）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_max_ms: Option<u64>,
    /// リングバッファ内の平均スキャン時間（ミリ秒）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_avg_ms: Option<u64>,
    /// 50 パーセンタイル（中央値）スキャン時間（ミリ秒）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_p50_ms: Option<u64>,
    /// 95 パーセンタイル スキャン時間（ミリ秒）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_p95_ms: Option<u64>,
    /// 99 パーセンタイル スキャン時間（ミリ秒）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_p99_ms: Option<u64>,
}

/// `/api/v1/stats/modules` レスポンスに対応するスナップショット構造体
///
/// `module-stats --save-snapshot` で保存される JSON ファイルと、
/// `--diff` でベースラインとして読み込む JSON の形式を表す。
///
/// `taken_at` は v1.61.0 以降で書き出される RFC3339 形式の保存時刻。
/// 古い v1.60.0 形式のスナップショット（フィールド無し）も `None` で読み込める。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatsSnapshot {
    /// スナップショット保存時刻（RFC3339 UTC 秒精度）。古い形式では存在しない。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taken_at: Option<String>,
    /// モジュール数
    pub total: usize,
    /// モジュール単位の統計の配列
    pub modules: Vec<ModuleStats>,
}

/// 単一モジュールの差分エントリ
///
/// ベースライン（過去スナップショット）と現時点の統計の差分を
/// 1 モジュール分表現する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatsDiffEntry {
    /// モジュール名
    pub module: String,
    /// `events_total` の差分（現在値 - ベースライン値）
    pub events_delta: i64,
    /// `events_info` の差分
    pub events_info_delta: i64,
    /// `events_warning` の差分
    pub events_warning_delta: i64,
    /// `events_critical` の差分
    pub events_critical_delta: i64,
    /// `scan_count` の差分
    pub scan_count_delta: i64,
    /// `scan_p50_ms` の差分（両者ともに値がある場合のみ）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_p50_ms_delta: Option<i64>,
    /// `scan_p95_ms` の差分
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_p95_ms_delta: Option<i64>,
    /// `scan_p99_ms` の差分
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_p99_ms_delta: Option<i64>,
    /// ベースラインに存在しなかった新規モジュールかどうか
    pub is_new: bool,
}

/// モジュール統計差分レポート
///
/// `module-stats --diff <SNAPSHOT>` の結果を表す。
/// `compute_diff` で生成する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatsDiffReport {
    /// ベースラインの取得時刻（わかる場合）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_taken_at: Option<String>,
    /// 現時点の取得時刻（RFC3339）
    pub current_taken_at: String,
    /// `events_total` の差分合計
    pub total_events_delta: i64,
    /// モジュール別の差分エントリ（モジュール名昇順）
    pub modules: Vec<ModuleStatsDiffEntry>,
}

/// ベースラインと現時点のモジュール統計から差分レポートを算出する
///
/// - `module_filter` が `Some(name)` の場合、その名前のモジュールのみ報告する
/// - ベースラインのみに存在するモジュール（削除済み）はレポートに含めない
/// - 現時点のみに存在するモジュール（新規）は `is_new = true` で報告する
/// - 百分位点 delta は両者の値が存在する場合のみ `Some` を返す
/// - `baseline_taken_at` はベースラインスナップショットの `taken_at` を伝搬させる
pub fn compute_diff(
    baseline: &[ModuleStats],
    current: &[ModuleStats],
    module_filter: Option<&str>,
    baseline_taken_at: Option<String>,
) -> ModuleStatsDiffReport {
    let baseline_map: HashMap<&str, &ModuleStats> =
        baseline.iter().map(|s| (s.module.as_str(), s)).collect();

    let mut entries: Vec<ModuleStatsDiffEntry> = Vec::new();
    for cur in current {
        if let Some(filter) = module_filter
            && cur.module != filter
        {
            continue;
        }
        let base = baseline_map.get(cur.module.as_str()).copied();
        entries.push(diff_entry(base, cur));
    }
    entries.sort_by(|a, b| a.module.cmp(&b.module));

    let total_events_delta: i64 = entries
        .iter()
        .fold(0i64, |acc, e| acc.saturating_add(e.events_delta));

    ModuleStatsDiffReport {
        baseline_taken_at,
        current_taken_at: current_rfc3339(),
        total_events_delta,
        modules: entries,
    }
}

fn diff_entry(base: Option<&ModuleStats>, cur: &ModuleStats) -> ModuleStatsDiffEntry {
    let is_new = base.is_none();
    let base_total = base.map(|b| b.events_total).unwrap_or(0);
    let base_info = base.map(|b| b.events_info).unwrap_or(0);
    let base_warn = base.map(|b| b.events_warning).unwrap_or(0);
    let base_crit = base.map(|b| b.events_critical).unwrap_or(0);
    let base_scan_count = base.map(|b| b.scan_count).unwrap_or(0);
    let module_name = cur.module.as_str();

    ModuleStatsDiffEntry {
        module: cur.module.clone(),
        events_delta: u64_diff(cur.events_total, base_total, module_name, "events_total"),
        events_info_delta: u64_diff(cur.events_info, base_info, module_name, "events_info"),
        events_warning_delta: u64_diff(
            cur.events_warning,
            base_warn,
            module_name,
            "events_warning",
        ),
        events_critical_delta: u64_diff(
            cur.events_critical,
            base_crit,
            module_name,
            "events_critical",
        ),
        scan_count_delta: u64_diff(cur.scan_count, base_scan_count, module_name, "scan_count"),
        scan_p50_ms_delta: option_diff(
            cur.scan_p50_ms,
            base.and_then(|b| b.scan_p50_ms),
            module_name,
            "scan_p50_ms",
        ),
        scan_p95_ms_delta: option_diff(
            cur.scan_p95_ms,
            base.and_then(|b| b.scan_p95_ms),
            module_name,
            "scan_p95_ms",
        ),
        scan_p99_ms_delta: option_diff(
            cur.scan_p99_ms,
            base.and_then(|b| b.scan_p99_ms),
            module_name,
            "scan_p99_ms",
        ),
        is_new,
    }
}

/// `u64` 値の差分を `i64` として算出する。
///
/// 差分が `i64` の表現範囲外になる場合は `i64::MAX` / `i64::MIN` にサチュレートし、
/// `tracing::warn!` で警告ログを出力する（モジュール名・メトリック名・current/baseline 付き）。
/// 実運用のイベント件数ではほぼ発生しないが、防御的に wrap-around を防ぐ。
fn u64_diff(current: u64, baseline: u64, module: &str, metric: &str) -> i64 {
    let diff = current as i128 - baseline as i128;
    if diff > i64::MAX as i128 {
        tracing::warn!(
            module = module,
            metric = metric,
            current = current,
            baseline = baseline,
            "module-stats diff saturated at i64::MAX"
        );
        i64::MAX
    } else if diff < i64::MIN as i128 {
        tracing::warn!(
            module = module,
            metric = metric,
            current = current,
            baseline = baseline,
            "module-stats diff saturated at i64::MIN"
        );
        i64::MIN
    } else {
        diff as i64
    }
}

fn option_diff(
    current: Option<u64>,
    baseline: Option<u64>,
    module: &str,
    metric: &str,
) -> Option<i64> {
    match (current, baseline) {
        (Some(c), Some(b)) => Some(u64_diff(c, b, module, metric)),
        _ => None,
    }
}

/// モジュール統計レジストリ内部の単一エントリ
///
/// `ModuleStats`（公開・シリアライズ用）に加え、百分位点を計算するための
/// サンプル用リングバッファ（`scan_samples_ms`）と累積合計（`scan_total_ms_acc`）を保持する。
#[derive(Debug, Clone, Default)]
struct Entry {
    stats: ModuleStats,
    /// 直近 `SCAN_HISTOGRAM_CAPACITY` 件までのスキャン時間（ミリ秒）
    scan_samples_ms: VecDeque<u64>,
    /// スキャン時間の累積合計（全期間・オーバーフロー防止のため u128）
    scan_total_ms_acc: u128,
}

/// モジュール統計レジストリ
///
/// 内部に `Arc<RwLock<HashMap<String, Entry>>>` を持ち、Clone 可能なハンドルとして共有する。
/// `Entry` は公開用 `ModuleStats` に加えてスキャン実行時間のリングバッファを保持し、
/// `snapshot()` 呼び出し時に百分位点（P50/P95/P99）などを算出する。
#[derive(Clone, Default)]
pub struct ModuleStatsHandle {
    inner: Arc<StdRwLock<HashMap<String, Entry>>>,
}

fn new_entry(module: &str) -> Entry {
    Entry {
        stats: ModuleStats {
            module: module.to_string(),
            ..Default::default()
        },
        scan_samples_ms: VecDeque::new(),
        scan_total_ms_acc: 0,
    }
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
            .or_insert_with(|| new_entry(module));
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
                .or_insert_with(|| new_entry(name));
        }
    }

    /// 起動時スキャン結果を記録する
    ///
    /// `initial_scan_*` フィールド（直近の起動時スキャン結果）を更新するとともに、
    /// スキャン実行時間ヒストグラムにもサンプルを追加する。
    pub fn record_initial_scan(
        &self,
        module: &str,
        duration: Duration,
        items: usize,
        issues: usize,
        summary: &str,
    ) {
        let duration_ms = duration.as_millis().min(u64::MAX as u128) as u64;
        // unwrap safety: RwLock が poisoned になるのはパニック時のみ
        let mut guard = self.inner.write().unwrap();
        let entry = guard
            .entry(module.to_string())
            .or_insert_with(|| new_entry(module));
        entry.stats.initial_scan_duration_ms = Some(duration_ms);
        entry.stats.initial_scan_items_scanned = Some(items);
        entry.stats.initial_scan_issues_found = Some(issues);
        entry.stats.initial_scan_summary = Some(summary.to_string());
        entry.stats.initial_scan_at = Some(current_rfc3339());
        push_scan_sample(entry, duration_ms);
    }

    /// スキャン実行時間サンプルを記録する（ヒストグラム用）
    ///
    /// 定期スキャン等から呼び出してサンプルを追加する。リングバッファの上限を超えると
    /// 最古のサンプルが破棄される。累積カウンタ（`scan_count` / `scan_total_ms_acc`）は
    /// すべてのサンプルを反映する。
    pub fn record_scan_duration(&self, module: &str, duration: Duration) {
        let duration_ms = duration.as_millis().min(u64::MAX as u128) as u64;
        // unwrap safety: RwLock が poisoned になるのはパニック時のみ
        let mut guard = self.inner.write().unwrap();
        let entry = guard
            .entry(module.to_string())
            .or_insert_with(|| new_entry(module));
        push_scan_sample(entry, duration_ms);
    }

    /// SecurityEvent を記録する（source_module 別の集計）
    pub fn record_event(&self, event: &SecurityEvent) {
        // unwrap safety: RwLock が poisoned になるのはパニック時のみ
        let mut guard = self.inner.write().unwrap();
        let entry = guard
            .entry(event.source_module.clone())
            .or_insert_with(|| new_entry(&event.source_module));
        let stats = &mut entry.stats;
        stats.events_total = stats.events_total.saturating_add(1);
        match event.severity {
            Severity::Info => stats.events_info = stats.events_info.saturating_add(1),
            Severity::Warning => stats.events_warning = stats.events_warning.saturating_add(1),
            Severity::Critical => stats.events_critical = stats.events_critical.saturating_add(1),
        }
        stats.last_event_at = Some(current_rfc3339());
    }

    /// 指定モジュールの統計を取得する（百分位点などを計算して返す）
    pub fn get(&self, module: &str) -> Option<ModuleStats> {
        // unwrap safety: RwLock が poisoned になるのはパニック時のみ
        let guard = self.inner.read().unwrap();
        guard.get(module).map(materialize_stats)
    }

    /// 全モジュールの統計をモジュール名でソートして返す
    ///
    /// 各モジュールについて、リングバッファから百分位点（P50/P95/P99）、最小/最大/平均、
    /// 累積合計を計算して返す。
    pub fn snapshot(&self) -> Vec<ModuleStats> {
        // unwrap safety: RwLock が poisoned になるのはパニック時のみ
        let guard = self.inner.read().unwrap();
        let mut list: Vec<ModuleStats> = guard.values().map(materialize_stats).collect();
        list.sort_by(|a, b| a.module.cmp(&b.module));
        list
    }
}

fn push_scan_sample(entry: &mut Entry, duration_ms: u64) {
    if entry.scan_samples_ms.len() >= SCAN_HISTOGRAM_CAPACITY {
        entry.scan_samples_ms.pop_front();
    }
    entry.scan_samples_ms.push_back(duration_ms);
    entry.stats.scan_count = entry.stats.scan_count.saturating_add(1);
    entry.scan_total_ms_acc = entry.scan_total_ms_acc.saturating_add(duration_ms as u128);
}

/// `Entry` からスナップショット用の `ModuleStats` を生成する
///
/// リングバッファの内容から百分位点・最小/最大/平均を計算し、
/// 累積合計（`scan_total_ms_acc`）を `scan_total_ms` として反映する。
fn materialize_stats(entry: &Entry) -> ModuleStats {
    let mut stats = entry.stats.clone();
    if entry.scan_samples_ms.is_empty() {
        stats.scan_total_ms = None;
        stats.scan_min_ms = None;
        stats.scan_max_ms = None;
        stats.scan_avg_ms = None;
        stats.scan_p50_ms = None;
        stats.scan_p95_ms = None;
        stats.scan_p99_ms = None;
    } else {
        let mut samples: Vec<u64> = entry.scan_samples_ms.iter().copied().collect();
        samples.sort_unstable();
        let min = samples.first().copied();
        let max = samples.last().copied();
        let sum: u128 = samples.iter().map(|v| *v as u128).sum();
        let avg = (sum / samples.len() as u128) as u64;
        stats.scan_min_ms = min;
        stats.scan_max_ms = max;
        stats.scan_avg_ms = Some(avg);
        stats.scan_p50_ms = Some(percentile_sorted(&samples, 50.0));
        stats.scan_p95_ms = Some(percentile_sorted(&samples, 95.0));
        stats.scan_p99_ms = Some(percentile_sorted(&samples, 99.0));
        stats.scan_total_ms = Some(entry.scan_total_ms_acc.min(u64::MAX as u128) as u64);
    }
    stats
}

/// ソート済みサンプル列から nearest-rank 法で百分位点を取り出す
///
/// `p` は 0.0 〜 100.0。空の入力では 0 を返す（呼び出し側で空チェック推奨）。
/// ランク計算: `ceil(p/100 * n)`（Wikipedia "Percentile — Nearest-rank method" 準拠）
fn percentile_sorted(sorted_samples: &[u64], p: f64) -> u64 {
    if sorted_samples.is_empty() {
        return 0;
    }
    let n = sorted_samples.len();
    let clamped = p.clamp(0.0, 100.0);
    if clamped <= 0.0 {
        return sorted_samples[0];
    }
    // nearest-rank: ceil(p/100 * n)、インデックスは rank-1
    let rank = ((clamped / 100.0) * n as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(n - 1);
    sorted_samples[idx]
}

/// 現在時刻を RFC3339 形式の文字列で返す（UTC 秒精度）
pub fn current_rfc3339() -> String {
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
    fn test_percentile_sorted_basic() {
        let samples: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile_sorted(&samples, 50.0), 50);
        assert_eq!(percentile_sorted(&samples, 95.0), 95);
        assert_eq!(percentile_sorted(&samples, 99.0), 99);
        assert_eq!(percentile_sorted(&samples, 100.0), 100);
    }

    #[test]
    fn test_percentile_sorted_edge_cases() {
        assert_eq!(percentile_sorted(&[], 50.0), 0);
        assert_eq!(percentile_sorted(&[42], 0.0), 42);
        assert_eq!(percentile_sorted(&[42], 50.0), 42);
        assert_eq!(percentile_sorted(&[42], 99.0), 42);
        assert_eq!(percentile_sorted(&[10, 20], 50.0), 10);
        assert_eq!(percentile_sorted(&[10, 20], 95.0), 20);
        // p=0 は最小値
        assert_eq!(percentile_sorted(&[5, 10, 15], 0.0), 5);
        // 範囲外は clamp される
        assert_eq!(percentile_sorted(&[1, 2, 3], -50.0), 1);
        assert_eq!(percentile_sorted(&[1, 2, 3], 500.0), 3);
    }

    #[test]
    fn test_record_scan_duration_populates_histogram() {
        let handle = ModuleStatsHandle::new();
        for ms in [10u64, 20, 30, 40, 50] {
            handle.record_scan_duration("m", Duration::from_millis(ms));
        }
        let s = handle.get("m").expect("m");
        assert_eq!(s.scan_count, 5);
        assert_eq!(s.scan_min_ms, Some(10));
        assert_eq!(s.scan_max_ms, Some(50));
        assert_eq!(s.scan_avg_ms, Some(30));
        assert_eq!(s.scan_total_ms, Some(150));
        // nearest-rank: ceil(0.5 * 5) = 3 -> idx 2 -> 30
        assert_eq!(s.scan_p50_ms, Some(30));
        // ceil(0.95 * 5) = 5 -> idx 4 -> 50
        assert_eq!(s.scan_p95_ms, Some(50));
        assert_eq!(s.scan_p99_ms, Some(50));
    }

    #[test]
    fn test_record_initial_scan_feeds_histogram() {
        let handle = ModuleStatsHandle::new();
        handle.record_initial_scan("m", Duration::from_millis(100), 10, 1, "summary");
        handle.record_initial_scan("m", Duration::from_millis(300), 10, 1, "summary");
        let s = handle.get("m").expect("m");
        assert_eq!(s.scan_count, 2);
        assert_eq!(s.scan_min_ms, Some(100));
        assert_eq!(s.scan_max_ms, Some(300));
        // 最新の initial_scan は 300ms
        assert_eq!(s.initial_scan_duration_ms, Some(300));
    }

    #[test]
    fn test_histogram_ring_buffer_caps_at_capacity() {
        let handle = ModuleStatsHandle::new();
        // 上限 + 余剰を投入
        for i in 0..(SCAN_HISTOGRAM_CAPACITY + 50) {
            handle.record_scan_duration("m", Duration::from_millis(i as u64));
        }
        let s = handle.get("m").expect("m");
        // scan_count は累積（破棄された分も含む）
        assert_eq!(s.scan_count as usize, SCAN_HISTOGRAM_CAPACITY + 50);
        // 最初の 50 件は破棄されているため、最小値は 50 以上
        assert!(s.scan_min_ms.unwrap() >= 50, "min={:?}", s.scan_min_ms);
        // 最大値は投入した最後の値
        assert_eq!(
            s.scan_max_ms,
            Some((SCAN_HISTOGRAM_CAPACITY + 50 - 1) as u64)
        );
    }

    #[test]
    fn test_no_histogram_when_no_samples() {
        let handle = ModuleStatsHandle::new();
        handle.ensure("m");
        let s = handle.get("m").expect("m");
        assert_eq!(s.scan_count, 0);
        assert_eq!(s.scan_p50_ms, None);
        assert_eq!(s.scan_p95_ms, None);
        assert_eq!(s.scan_p99_ms, None);
        assert_eq!(s.scan_min_ms, None);
        assert_eq!(s.scan_max_ms, None);
        assert_eq!(s.scan_avg_ms, None);
        assert_eq!(s.scan_total_ms, None);
    }

    #[test]
    fn test_histogram_serialized_with_samples() {
        let handle = ModuleStatsHandle::new();
        handle.record_scan_duration("m", Duration::from_millis(100));
        handle.record_scan_duration("m", Duration::from_millis(200));
        let s = handle.get("m").expect("m");
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"scan_count\":2"));
        assert!(json.contains("\"scan_p50_ms\":100"));
        assert!(json.contains("\"scan_p95_ms\":200"));
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

    fn mk_stats(module: &str, total: u64, p50: Option<u64>, p95: Option<u64>) -> ModuleStats {
        ModuleStats {
            module: module.to_string(),
            events_total: total,
            events_info: total,
            events_warning: 0,
            events_critical: 0,
            scan_count: total,
            scan_p50_ms: p50,
            scan_p95_ms: p95,
            scan_p99_ms: p95,
            ..Default::default()
        }
    }

    #[test]
    fn test_compute_diff_basic() {
        let baseline = vec![
            mk_stats("mod_a", 10, Some(5), Some(20)),
            mk_stats("mod_b", 2, Some(1), Some(4)),
        ];
        let current = vec![
            mk_stats("mod_a", 15, Some(6), Some(25)),
            mk_stats("mod_b", 2, Some(1), Some(4)),
        ];
        let report = compute_diff(&baseline, &current, None, None);
        assert_eq!(report.modules.len(), 2);
        assert_eq!(report.total_events_delta, 5);

        let a = report.modules.iter().find(|m| m.module == "mod_a").unwrap();
        assert_eq!(a.events_delta, 5);
        assert_eq!(a.events_info_delta, 5);
        assert_eq!(a.scan_p50_ms_delta, Some(1));
        assert_eq!(a.scan_p95_ms_delta, Some(5));
        assert!(!a.is_new);

        let b = report.modules.iter().find(|m| m.module == "mod_b").unwrap();
        assert_eq!(b.events_delta, 0);
        assert_eq!(b.scan_p50_ms_delta, Some(0));
    }

    #[test]
    fn test_compute_diff_module_only_in_baseline_is_excluded() {
        let baseline = vec![
            mk_stats("mod_a", 10, Some(5), Some(20)),
            mk_stats("removed_mod", 99, Some(100), Some(200)),
        ];
        let current = vec![mk_stats("mod_a", 11, Some(5), Some(20))];
        let report = compute_diff(&baseline, &current, None, None);
        assert_eq!(report.modules.len(), 1);
        assert_eq!(report.modules[0].module, "mod_a");
    }

    #[test]
    fn test_compute_diff_module_only_in_current_is_new() {
        let baseline = vec![mk_stats("mod_a", 10, Some(5), Some(20))];
        let current = vec![
            mk_stats("mod_a", 10, Some(5), Some(20)),
            mk_stats("new_mod", 7, Some(3), Some(12)),
        ];
        let report = compute_diff(&baseline, &current, None, None);
        let new_mod = report
            .modules
            .iter()
            .find(|m| m.module == "new_mod")
            .unwrap();
        assert!(new_mod.is_new);
        assert_eq!(new_mod.events_delta, 7);
        assert_eq!(new_mod.events_info_delta, 7);
        // 百分位点はベースラインに値がないので None
        assert_eq!(new_mod.scan_p50_ms_delta, None);
        assert_eq!(new_mod.scan_p95_ms_delta, None);
    }

    #[test]
    fn test_compute_diff_module_filter() {
        let baseline = vec![
            mk_stats("mod_a", 10, Some(5), Some(20)),
            mk_stats("mod_b", 3, Some(2), Some(8)),
        ];
        let current = vec![
            mk_stats("mod_a", 12, Some(5), Some(20)),
            mk_stats("mod_b", 4, Some(2), Some(8)),
        ];
        let report = compute_diff(&baseline, &current, Some("mod_b"), None);
        assert_eq!(report.modules.len(), 1);
        assert_eq!(report.modules[0].module, "mod_b");
        assert_eq!(report.modules[0].events_delta, 1);
        assert_eq!(report.total_events_delta, 1);
    }

    #[test]
    fn test_compute_diff_percentile_none_yields_none() {
        let baseline = vec![mk_stats("mod_a", 10, Some(5), None)];
        let current = vec![mk_stats("mod_a", 10, None, Some(20))];
        let report = compute_diff(&baseline, &current, None, None);
        let a = &report.modules[0];
        assert_eq!(a.scan_p50_ms_delta, None);
        assert_eq!(a.scan_p95_ms_delta, None);
    }

    #[test]
    fn test_compute_diff_negative_delta() {
        let baseline = vec![mk_stats("mod_a", 20, Some(50), Some(100))];
        let current = vec![mk_stats("mod_a", 15, Some(40), Some(80))];
        let report = compute_diff(&baseline, &current, None, None);
        assert_eq!(report.modules[0].events_delta, -5);
        assert_eq!(report.modules[0].scan_p50_ms_delta, Some(-10));
        assert_eq!(report.modules[0].scan_p95_ms_delta, Some(-20));
        assert_eq!(report.total_events_delta, -5);
    }

    #[test]
    fn test_module_stats_snapshot_serde_roundtrip() {
        let snapshot = ModuleStatsSnapshot {
            taken_at: None,
            total: 2,
            modules: vec![
                mk_stats("mod_a", 1, Some(10), Some(20)),
                mk_stats("mod_b", 2, Some(5), Some(15)),
            ],
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: ModuleStatsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total, 2);
        assert_eq!(parsed.modules.len(), 2);
        assert_eq!(parsed.modules[0].module, "mod_a");
        assert_eq!(parsed.taken_at, None);
    }

    #[test]
    fn test_module_stats_snapshot_serde_with_taken_at() {
        let snapshot = ModuleStatsSnapshot {
            taken_at: Some("2026-04-18T12:34:56Z".into()),
            total: 1,
            modules: vec![mk_stats("mod_a", 1, Some(10), Some(20))],
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(
            json.contains("\"taken_at\":\"2026-04-18T12:34:56Z\""),
            "taken_at field missing from JSON: {}",
            json
        );
        let parsed: ModuleStatsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.taken_at.as_deref(), Some("2026-04-18T12:34:56Z"));
        assert_eq!(parsed.total, 1);
    }

    #[test]
    fn test_module_stats_snapshot_serde_without_taken_at_backward_compat() {
        // v1.60.0 形式: taken_at フィールドが存在しない JSON
        let json = r#"{"total":1,"modules":[{"module":"mod_a","events_total":0,"events_info":0,"events_warning":0,"events_critical":0,"scan_count":0}]}"#;
        let parsed: ModuleStatsSnapshot = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.taken_at, None);
        assert_eq!(parsed.total, 1);
        assert_eq!(parsed.modules.len(), 1);
        assert_eq!(parsed.modules[0].module, "mod_a");
    }

    #[test]
    fn test_compute_diff_propagates_baseline_taken_at() {
        let baseline = vec![mk_stats("mod_a", 10, Some(5), Some(20))];
        let current = vec![mk_stats("mod_a", 11, Some(5), Some(20))];
        let report = compute_diff(
            &baseline,
            &current,
            None,
            Some("2026-04-18T10:00:00Z".into()),
        );
        assert_eq!(
            report.baseline_taken_at.as_deref(),
            Some("2026-04-18T10:00:00Z")
        );
    }

    #[test]
    fn test_compute_diff_saturates_at_i64_max_when_overflowing_positive() {
        // baseline=0, current=u64::MAX → 差分は u64::MAX (≒ 1.8e19) で i64::MAX (≒ 9.2e18) を超える
        let baseline = vec![mk_stats("mod_a", 0, None, None)];
        let current = vec![mk_stats("mod_a", u64::MAX, None, None)];
        let report = compute_diff(&baseline, &current, None, None);
        assert_eq!(report.modules.len(), 1);
        let a = &report.modules[0];
        assert_eq!(a.events_delta, i64::MAX);
        assert_eq!(a.events_info_delta, i64::MAX);
        assert_eq!(a.scan_count_delta, i64::MAX);
    }

    #[test]
    fn test_compute_diff_saturates_at_i64_min_when_overflowing_negative() {
        // baseline=u64::MAX, current=0 → 差分は -(u64::MAX) で i64::MIN を下回る
        let baseline = vec![mk_stats("mod_a", u64::MAX, None, None)];
        let current = vec![mk_stats("mod_a", 0, None, None)];
        let report = compute_diff(&baseline, &current, None, None);
        let a = &report.modules[0];
        assert_eq!(a.events_delta, i64::MIN);
        assert_eq!(a.events_info_delta, i64::MIN);
        assert_eq!(a.scan_count_delta, i64::MIN);
    }

    #[test]
    fn test_compute_diff_total_events_delta_saturates_on_sum_overflow() {
        // i64::MAX/2 + 100 の delta が複数モジュールで発生し、合計が i64::MAX を超過するケース。
        // saturating_add で i64::MAX に clamp されることを確認する。
        let big = (i64::MAX / 2) as u64 + 100;
        let baseline = vec![
            mk_stats("mod_a", 0, None, None),
            mk_stats("mod_b", 0, None, None),
            mk_stats("mod_c", 0, None, None),
        ];
        let current = vec![
            mk_stats("mod_a", big, None, None),
            mk_stats("mod_b", big, None, None),
            mk_stats("mod_c", big, None, None),
        ];
        let report = compute_diff(&baseline, &current, None, None);
        // 3 モジュール × (i64::MAX/2 + 100) ≒ 1.5 × i64::MAX なので i64::MAX に saturate
        assert_eq!(report.total_events_delta, i64::MAX);
    }

    #[test]
    fn test_compute_diff_total_events_delta_normal_sum_unaffected() {
        // 通常範囲での合計は saturating_add 化しても結果が変わらないことを確認する
        let baseline = vec![
            mk_stats("mod_a", 100, None, None),
            mk_stats("mod_b", 200, None, None),
        ];
        let current = vec![
            mk_stats("mod_a", 150, None, None),
            mk_stats("mod_b", 250, None, None),
        ];
        let report = compute_diff(&baseline, &current, None, None);
        assert_eq!(report.total_events_delta, 100);
    }

    #[test]
    fn test_compute_diff_saturates_percentile_delta() {
        // 百分位点 delta も同様に saturate することを確認する
        let baseline = vec![mk_stats("mod_a", 0, Some(u64::MAX), None)];
        let current = vec![mk_stats("mod_a", 0, Some(0), None)];
        let report = compute_diff(&baseline, &current, None, None);
        let a = &report.modules[0];
        // u64::MAX → 0 の差分は i64::MIN にサチュレート
        assert_eq!(a.scan_p50_ms_delta, Some(i64::MIN));
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
