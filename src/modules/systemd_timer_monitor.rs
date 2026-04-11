//! systemd タイマー監視モジュー��
//!
//! systemd タイマーユニットファイル（`.timer`）を定期的にスキャンし、SHA-256 ハッシュベースで変更を検知する。
//!
//! 検知対象:
//! - 新規追加された systemd タイマーユニットファイル
//! - 内容が変更された systemd タイマーユニットファ��ル
//! - 削除された systemd タイマーユニットファイル
//! - 不審なタイマー設定（短すぎるインターバル、対応サービスファイルの欠如）

use crate::config::SystemdTimerMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// systemd タイマーユニットファイル変更レポート
struct ChangeReport {
    modified: Vec<PathBuf>,
    added: Vec<PathBuf>,
    removed: Vec<PathBuf>,
}

impl ChangeReport {
    /// 変更があったかどうかを返す
    fn has_changes(&self) -> bool {
        !self.modified.is_empty() || !self.added.is_empty() || !self.removed.is_empty()
    }
}

/// 不審なタイマー設定の検知結果
struct SuspiciousReport {
    short_interval: Vec<(PathBuf, u64)>,
    missing_service: Vec<PathBuf>,
}

impl SuspiciousReport {
    fn has_issues(&self) -> bool {
        !self.short_interval.is_empty() || !self.missing_service.is_empty()
    }
}

/// systemd タイマー監視モジュール
///
/// systemd タイマーユニットファイル（`.timer`）を定期スキャンし、
/// ベースラインとの差分および不審な設定を検知する。
pub struct SystemdTimerMonitorModule {
    config: SystemdTimerMonitorConfig,
    event_bus: Option<EventBus>,
    baseline: Option<HashMap<PathBuf, String>>,
    cancel_token: CancellationToken,
}

impl SystemdTimerMonitorModule {
    /// 新しい systemd タイマー監視モジュールを作成する
    pub fn new(config: SystemdTimerMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            event_bus,
            baseline: None,
            cancel_token: CancellationToken::new(),
        }
    }

    /// キャンセル���ークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// 監視対象ディレクトリから `.timer` ファイルをスキャンし、各ファイルの SHA-256 ハッシュを返す
    fn scan_timer_files(timer_dirs: &[PathBuf]) -> HashMap<PathBuf, String> {
        let mut result = HashMap::new();
        for dir in timer_dirs {
            if !dir.is_dir() {
                continue;
            }
            let entries = match std::fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(e) => {
                    tracing::warn!(
                        dir = %dir.display(),
                        error = %e,
                        "タイマー���ィレクトリの読み取りに失敗しました"
                    );
                    continue;
                }
            };
            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!(error = %e, "ディレクトリエントリの読み取りに失敗しました");
                        continue;
                    }
                };
                let path = entry.path();
                if path.is_file() && path.extension().is_some_and(|ext| ext == "timer") {
                    match compute_hash(&path) {
                        Ok(hash) => {
                            result.insert(path, hash);
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %path.display(),
                                error = %e,
                                "タイマーファイルの読み取りに失敗しました"
                            );
                        }
                    }
                }
            }
        }
        result
    }

    /// ベースラインと現在のスキャン結果を比較し、変更レポートを返す
    fn detect_changes(
        baseline: &HashMap<PathBuf, String>,
        current: &HashMap<PathBuf, String>,
    ) -> ChangeReport {
        let mut modified = Vec::new();
        let mut added = Vec::new();
        let mut removed = Vec::new();

        for (path, current_hash) in current {
            match baseline.get(path) {
                Some(baseline_hash) if baseline_hash != current_hash => {
                    modified.push(path.clone());
                }
                None => {
                    added.push(path.clone());
                }
                _ => {}
            }
        }

        for path in baseline.keys() {
            if !current.contains_key(path) {
                removed.push(path.clone());
            }
        }

        ChangeReport {
            modified,
            added,
            removed,
        }
    }

    /// タイマーファイルの不審な設定を検査す���
    fn check_suspicious(
        timer_files: &HashMap<PathBuf, String>,
        min_interval_warn_seconds: u64,
    ) -> SuspiciousReport {
        let mut short_interval = Vec::new();
        let mut missing_service = Vec::new();

        for path in timer_files.keys() {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // インターバルチェック
            if let Some(seconds) = parse_timer_interval(&content)
                && seconds > 0
                && seconds < min_interval_warn_seconds
            {
                short_interval.push((path.clone(), seconds));
            }

            // 対応サービスファイルの存在チェック
            if !has_corresponding_service(path, &content) {
                missing_service.push(path.clone());
            }
        }

        SuspiciousReport {
            short_interval,
            missing_service,
        }
    }
}

/// タイマーファイルからインターバル秒数をパースする
///
/// `OnUnitActiveSec=` や `OnBootSec=` の値を秒数に変換する。
/// 複数ある場合は最小値を返す。
fn parse_timer_interval(content: &str) -> Option<u64> {
    let mut min_seconds: Option<u64> = None;
    let in_timer_section = content.contains("[Timer]");
    if !in_timer_section {
        return None;
    }

    for line in content.lines() {
        let trimmed = line.trim();
        for prefix in &["OnUnitActiveSec=", "OnBootSec="] {
            if let Some(value) = trimmed.strip_prefix(prefix)
                && let Some(secs) = parse_systemd_time_span(value.trim())
            {
                min_seconds = Some(min_seconds.map_or(secs, |current| current.min(secs)));
            }
        }
    }

    min_seconds
}

/// systemd の時間指定文字列を秒数に変換する
///
/// 対応形式:
/// - 純粋な数値（秒として解釈）
/// - `Ns`, `Nmin`, `Nh`, `Nd`, `Nw`（単位付き）
/// - 複合形式（例: `1h 30min`��
fn parse_systemd_time_span(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    // 純粋な数値の場合はマイクロ秒として解釈（systemd のデフォルト）
    if let Ok(n) = value.parse::<u64>() {
        // systemd は単位なし数値をマイクロ秒として扱う
        return Some(n / 1_000_000);
    }

    let mut total_seconds: u64 = 0;
    let mut current_num = String::new();
    let mut chars = value.chars().peekable();
    let mut has_match = false;

    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            current_num.push(c);
            chars.next();
        } else if c.is_ascii_alphabetic() {
            let mut unit = String::new();
            while let Some(&u) = chars.peek() {
                if u.is_ascii_alphabetic() {
                    unit.push(u);
                    chars.next();
                } else {
                    break;
                }
            }

            let num: u64 = if current_num.is_empty() {
                return None;
            } else {
                match current_num.parse() {
                    Ok(n) => n,
                    Err(_) => return None,
                }
            };

            let multiplier = match unit.as_str() {
                "us" | "usec" => {
                    current_num.clear();
                    has_match = true;
                    // マイクロ秒は 0 秒に丸める
                    total_seconds += 0;
                    continue;
                }
                "ms" | "msec" => {
                    current_num.clear();
                    has_match = true;
                    // ミリ秒は 0 秒に丸める
                    total_seconds += 0;
                    continue;
                }
                "s" | "sec" | "second" | "seconds" => 1u64,
                "min" | "minute" | "minutes" | "m" => 60,
                "h" | "hr" | "hour" | "hours" => 3600,
                "d" | "day" | "days" => 86400,
                "w" | "week" | "weeks" => 604_800,
                _ => return None,
            };

            total_seconds += num * multiplier;
            current_num.clear();
            has_match = true;
        } else if c == ' ' {
            chars.next();
        } else {
            return None;
        }
    }

    if has_match { Some(total_seconds) } else { None }
}

/// 対応する `.service` ファイルが存在するかチェックする
fn has_corresponding_service(timer_path: &Path, content: &str) -> bool {
    // Unit= ディレクティブで明示的に指定されている場合
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(unit_value) = trimmed.strip_prefix("Unit=") {
            let unit_name = unit_value.trim();
            if !unit_name.is_empty() {
                // 同じディレクトリ内で探す
                if let Some(parent) = timer_path.parent() {
                    let service_path = parent.join(unit_name);
                    if service_path.exists() {
                        return true;
                    }
                }
                // 他の systemd ディレクトリでも探す
                let standard_dirs = [
                    "/etc/systemd/system",
                    "/usr/lib/systemd/system",
                    "/run/systemd/system",
                ];
                for dir in &standard_dirs {
                    let service_path = PathBuf::from(dir).join(unit_name);
                    if service_path.exists() {
                        return true;
                    }
                }
                return false;
            }
        }
    }

    // 明示的な Unit= がない場合、同名の .service ファイルを探す
    let service_name = timer_path.with_extension("service");
    if service_name.exists() {
        return true;
    }

    // 同じディレクトリ内と他の標準ディレクトリで同名 .service を探す
    if let Some(file_name) = timer_path.file_stem() {
        let service_file = format!("{}.service", file_name.to_string_lossy());
        let standard_dirs = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
        ];
        for dir in &standard_dirs {
            let service_path = PathBuf::from(dir).join(&service_file);
            if service_path.exists() {
                return true;
            }
        }
    }

    false
}

/// ファイ���の SHA-256 ハッシュを���算する
fn compute_hash(path: &Path) -> Result<String, AppError> {
    let data = std::fs::read(path).map_err(|e| AppError::FileIo {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}

impl Module for SystemdTimerMonitorModule {
    fn name(&self) -> &str {
        "systemd_timer_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してくださ��".to_string(),
            });
        }

        // パストラバーサル防止: canonicalize でパスを正規化
        let mut canonicalized = Vec::new();
        for path in &self.config.timer_dirs {
            match std::fs::canonicalize(path) {
                Ok(canonical) => canonicalized.push(canonical),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "監視対象パスが存在しないためスキップします"
                    );
                }
            }
        }
        self.config.timer_dirs = canonicalized;

        tracing::info!(
            timer_dirs = ?self.config.timer_dirs,
            scan_interval_secs = self.config.scan_interval_secs,
            min_interval_warn_seconds = self.config.min_interval_warn_seconds,
            "systemd タイマー監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        // 初回スキャンでベースライン作成
        let baseline = Self::scan_timer_files(&self.config.timer_dirs);
        tracing::info!(
            file_count = baseline.len(),
            "タイマーユニットのベースラインスキャンが完了しました"
        );

        self.baseline = Some(baseline);

        let mut baseline = self.baseline.take().ok_or_else(|| AppError::ModuleConfig {
            message: "ベースラインが未初期化です".to_string(),
        })?;

        let timer_dirs = self.config.timer_dirs.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let min_interval_warn_seconds = self.config.min_interval_warn_seconds;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("systemd タイマー監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = SystemdTimerMonitorModule::scan_timer_files(&timer_dirs);
                        let report = SystemdTimerMonitorModule::detect_changes(&baseline, &current);

                        if report.has_changes() {
                            for path in &report.modified {
                                tracing::warn!(path = %path.display(), change = "modified", "systemd タイマーユニットの変更を検知しました");
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "systemd_timer_modified",
                                            Severity::Critical,
                                            "systemd_timer_monitor",
                                            format!("systemd タイマーユニットの変更を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            for path in &report.added {
                                tracing::warn!(path = %path.display(), change = "added", "systemd タ���マーユニットの追加を検知しました");
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "systemd_timer_added",
                                            Severity::Critical,
                                            "systemd_timer_monitor",
                                            format!("systemd タイマーユニットの追加を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            for path in &report.removed {
                                tracing::warn!(path = %path.display(), change = "removed", "systemd タイ���ーユニ��トの削除を検知しました");
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "systemd_timer_removed",
                                            Severity::Warning,
                                            "systemd_timer_monitor",
                                            format!("systemd タイマーユニットの削除を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            // ベースラインを更新
                            baseline = current.clone();
                        } else {
                            tracing::debug!("systemd タイマーユニットの変更はありません");
                        }

                        // 不審なタイマー設定チェック
                        let suspicious = SystemdTimerMonitorModule::check_suspicious(
                            &current,
                            min_interval_warn_seconds,
                        );
                        if suspicious.has_issues() {
                            for (path, seconds) in &suspicious.short_interval {
                                tracing::warn!(
                                    path = %path.display(),
                                    interval_seconds = seconds,
                                    "不審に短いインターバルのタイマーを検知しました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "systemd_timer_suspicious_interval",
                                            Severity::Critical,
                                            "systemd_timer_monitor",
                                            format!(
                                                "不審に短いインターバル（{}秒）のタイマーを検知しました: {}",
                                                seconds,
                                                path.display()
                                            ),
                                        )
                                        .with_details(format!(
                                            "interval={}s, path={}",
                                            seconds,
                                            path.display()
                                        )),
                                    );
                                }
                            }
                            for path in &suspicious.missing_service {
                                tracing::warn!(
                                    path = %path.display(),
                                    "対応するサービスファイルが存在しないタイマーを検知しました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "systemd_timer_missing_service",
                                            Severity::Critical,
                                            "systemd_timer_monitor",
                                            format!(
                                                "対応するサービスファイルが存在しないタイマーを検知しました: {}",
                                                path.display()
                                            ),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let files = Self::scan_timer_files(&self.config.timer_dirs);
        let items_scanned = files.len();

        // 不審な設定をチェック
        let suspicious = Self::check_suspicious(&files, self.config.min_interval_warn_seconds);
        let issues_found = suspicious.short_interval.len() + suspicious.missing_service.len();

        let snapshot: BTreeMap<String, String> = files
            .iter()
            .map(|(path, hash)| (path.display().to_string(), hash.clone()))
            .collect();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "systemd タイマーユニット {}件をスキャン、不審な設定 {}件を検知しました",
                items_scanned, issues_found
            ),
            snapshot,
        })
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_compute_hash() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "hello world").unwrap();
        let hash = compute_hash(tmpfile.path()).unwrap();
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_hash_nonexistent() {
        let result = compute_hash(Path::new("/tmp/nonexistent-file-zettai-timer-test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_timer_files_only_timer_extension() {
        let dir = tempfile::tempdir().unwrap();
        let timer_file = dir.path().join("test.timer");
        let service_file = dir.path().join("test.service");
        let other_file = dir.path().join("test.conf");
        std::fs::write(&timer_file, "[Timer]\nOnBootSec=5min").unwrap();
        std::fs::write(&service_file, "[Service]\nExecStart=/bin/true").unwrap();
        std::fs::write(&other_file, "some config").unwrap();

        let timer_dirs = vec![dir.path().to_path_buf()];
        let result = SystemdTimerMonitorModule::scan_timer_files(&timer_dirs);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&timer_file));
        assert!(!result.contains_key(&service_file));
    }

    #[test]
    fn test_scan_timer_files_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let timer_dirs = vec![dir.path().to_path_buf()];
        let result = SystemdTimerMonitorModule::scan_timer_files(&timer_dirs);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_timer_files_nonexistent_dir() {
        let timer_dirs = vec![PathBuf::from("/nonexistent-dir-zettai-timer-test")];
        let result = SystemdTimerMonitorModule::scan_timer_files(&timer_dirs);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_timer_files_multiple_dirs() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        std::fs::write(dir1.path().join("a.timer"), "[Timer]").unwrap();
        std::fs::write(dir2.path().join("b.timer"), "[Timer]").unwrap();

        let timer_dirs = vec![dir1.path().to_path_buf(), dir2.path().to_path_buf()];
        let result = SystemdTimerMonitorModule::scan_timer_files(&timer_dirs);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_detect_changes_no_changes() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/test/a.timer"), "hash1".to_string());
        let current = baseline.clone();
        let report = SystemdTimerMonitorModule::detect_changes(&baseline, &current);
        assert!(!report.has_changes());
    }

    #[test]
    fn test_detect_changes_modified() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/test/a.timer"), "hash1".to_string());
        let mut current = HashMap::new();
        current.insert(PathBuf::from("/test/a.timer"), "hash2".to_string());
        let report = SystemdTimerMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(report.modified.len(), 1);
        assert!(report.added.is_empty());
        assert!(report.removed.is_empty());
    }

    #[test]
    fn test_detect_changes_added() {
        let baseline = HashMap::new();
        let mut current = HashMap::new();
        current.insert(PathBuf::from("/test/new.timer"), "hash1".to_string());
        let report = SystemdTimerMonitorModule::detect_changes(&baseline, &current);
        assert!(report.modified.is_empty());
        assert_eq!(report.added.len(), 1);
        assert!(report.removed.is_empty());
    }

    #[test]
    fn test_detect_changes_removed() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/test/old.timer"), "hash1".to_string());
        let current = HashMap::new();
        let report = SystemdTimerMonitorModule::detect_changes(&baseline, &current);
        assert!(report.modified.is_empty());
        assert!(report.added.is_empty());
        assert_eq!(report.removed.len(), 1);
    }

    #[test]
    fn test_detect_changes_combined() {
        let mut baseline = HashMap::new();
        baseline.insert(PathBuf::from("/test/unchanged.timer"), "hash1".to_string());
        baseline.insert(PathBuf::from("/test/to_remove.timer"), "hash2".to_string());
        baseline.insert(PathBuf::from("/test/to_modify.timer"), "hash3".to_string());

        let mut current = HashMap::new();
        current.insert(PathBuf::from("/test/unchanged.timer"), "hash1".to_string());
        current.insert(
            PathBuf::from("/test/to_modify.timer"),
            "hash_changed".to_string(),
        );
        current.insert(PathBuf::from("/test/new.timer"), "hash4".to_string());

        let report = SystemdTimerMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(report.modified.len(), 1);
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.removed.len(), 1);
    }

    #[test]
    fn test_parse_systemd_time_span_seconds() {
        assert_eq!(parse_systemd_time_span("30s"), Some(30));
        assert_eq!(parse_systemd_time_span("1sec"), Some(1));
        assert_eq!(parse_systemd_time_span("60seconds"), Some(60));
    }

    #[test]
    fn test_parse_systemd_time_span_minutes() {
        assert_eq!(parse_systemd_time_span("5min"), Some(300));
        assert_eq!(parse_systemd_time_span("1m"), Some(60));
        assert_eq!(parse_systemd_time_span("2minute"), Some(120));
    }

    #[test]
    fn test_parse_systemd_time_span_hours() {
        assert_eq!(parse_systemd_time_span("1h"), Some(3600));
        assert_eq!(parse_systemd_time_span("2hr"), Some(7200));
    }

    #[test]
    fn test_parse_systemd_time_span_days() {
        assert_eq!(parse_systemd_time_span("1d"), Some(86400));
        assert_eq!(parse_systemd_time_span("7day"), Some(604800));
    }

    #[test]
    fn test_parse_systemd_time_span_weeks() {
        assert_eq!(parse_systemd_time_span("1w"), Some(604800));
    }

    #[test]
    fn test_parse_systemd_time_span_compound() {
        assert_eq!(parse_systemd_time_span("1h 30min"), Some(5400));
        assert_eq!(parse_systemd_time_span("1d 12h"), Some(129600));
    }

    #[test]
    fn test_parse_systemd_time_span_bare_number() {
        // systemd は単位なし数値をマイクロ秒として扱う
        assert_eq!(parse_systemd_time_span("1000000"), Some(1));
        assert_eq!(parse_systemd_time_span("0"), Some(0));
    }

    #[test]
    fn test_parse_systemd_time_span_empty() {
        assert_eq!(parse_systemd_time_span(""), None);
    }

    #[test]
    fn test_parse_systemd_time_span_invalid() {
        assert_eq!(parse_systemd_time_span("abc"), None);
    }

    #[test]
    fn test_parse_timer_interval_on_boot_sec() {
        let content = "[Timer]\nOnBootSec=30s\n";
        assert_eq!(parse_timer_interval(content), Some(30));
    }

    #[test]
    fn test_parse_timer_interval_on_unit_active_sec() {
        let content = "[Timer]\nOnUnitActiveSec=5min\n";
        assert_eq!(parse_timer_interval(content), Some(300));
    }

    #[test]
    fn test_parse_timer_interval_multiple_takes_min() {
        let content = "[Timer]\nOnBootSec=1h\nOnUnitActiveSec=5min\n";
        assert_eq!(parse_timer_interval(content), Some(300));
    }

    #[test]
    fn test_parse_timer_interval_no_timer_section() {
        let content = "[Unit]\nDescription=Test\n";
        assert_eq!(parse_timer_interval(content), None);
    }

    #[test]
    fn test_parse_timer_interval_no_interval_keys() {
        let content = "[Timer]\nOnCalendar=daily\n";
        assert_eq!(parse_timer_interval(content), None);
    }

    #[test]
    fn test_has_corresponding_service_same_dir() {
        let dir = tempfile::tempdir().unwrap();
        let timer_path = dir.path().join("test.timer");
        let service_path = dir.path().join("test.service");
        std::fs::write(&timer_path, "[Timer]\nOnBootSec=5min").unwrap();
        std::fs::write(&service_path, "[Service]\nExecStart=/bin/true").unwrap();

        assert!(has_corresponding_service(
            &timer_path,
            "[Timer]\nOnBootSec=5min"
        ));
    }

    #[test]
    fn test_has_corresponding_service_missing() {
        let dir = tempfile::tempdir().unwrap();
        let timer_path = dir.path().join("orphan.timer");
        std::fs::write(&timer_path, "[Timer]\nOnBootSec=5min").unwrap();

        assert!(!has_corresponding_service(
            &timer_path,
            "[Timer]\nOnBootSec=5min"
        ));
    }

    #[test]
    fn test_has_corresponding_service_explicit_unit() {
        let dir = tempfile::tempdir().unwrap();
        let timer_path = dir.path().join("test.timer");
        let service_path = dir.path().join("my-service.service");
        std::fs::write(&timer_path, "[Timer]\nUnit=my-service.service").unwrap();
        std::fs::write(&service_path, "[Service]\nExecStart=/bin/true").unwrap();

        let content = "[Timer]\nUnit=my-service.service";
        assert!(has_corresponding_service(&timer_path, content));
    }

    #[test]
    fn test_check_suspicious_short_interval() {
        let dir = tempfile::tempdir().unwrap();
        let timer_path = dir.path().join("fast.timer");
        let service_path = dir.path().join("fast.service");
        std::fs::write(&timer_path, "[Timer]\nOnBootSec=10s").unwrap();
        std::fs::write(&service_path, "[Service]\nExecStart=/bin/true").unwrap();

        let mut files = HashMap::new();
        files.insert(timer_path, "hash".to_string());

        let report = SystemdTimerMonitorModule::check_suspicious(&files, 60);
        assert_eq!(report.short_interval.len(), 1);
        assert_eq!(report.short_interval[0].1, 10);
    }

    #[test]
    fn test_check_suspicious_normal_interval() {
        let dir = tempfile::tempdir().unwrap();
        let timer_path = dir.path().join("normal.timer");
        let service_path = dir.path().join("normal.service");
        std::fs::write(&timer_path, "[Timer]\nOnBootSec=5min").unwrap();
        std::fs::write(&service_path, "[Service]\nExecStart=/bin/true").unwrap();

        let mut files = HashMap::new();
        files.insert(timer_path, "hash".to_string());

        let report = SystemdTimerMonitorModule::check_suspicious(&files, 60);
        assert!(report.short_interval.is_empty());
    }

    #[test]
    fn test_check_suspicious_missing_service() {
        let dir = tempfile::tempdir().unwrap();
        let timer_path = dir.path().join("orphan.timer");
        std::fs::write(&timer_path, "[Timer]\nOnBootSec=5min").unwrap();

        let mut files = HashMap::new();
        files.insert(timer_path, "hash".to_string());

        let report = SystemdTimerMonitorModule::check_suspicious(&files, 60);
        assert_eq!(report.missing_service.len(), 1);
    }

    #[test]
    fn test_init_zero_interval() {
        let config = SystemdTimerMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            timer_dirs: vec![],
            min_interval_warn_seconds: 60,
        };
        let mut module = SystemdTimerMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let dir = tempfile::tempdir().unwrap();
        let config = SystemdTimerMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            timer_dirs: vec![dir.path().to_path_buf()],
            min_interval_warn_seconds: 60,
        };
        let mut module = SystemdTimerMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_nonexistent_path() {
        let config = SystemdTimerMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            timer_dirs: vec![PathBuf::from("/nonexistent-path-zettai-timer-test")],
            min_interval_warn_seconds: 60,
        };
        let mut module = SystemdTimerMonitorModule::new(config, None);
        assert!(module.init().is_ok());
        assert!(module.config.timer_dirs.is_empty());
    }

    #[test]
    fn test_init_canonicalizes_paths() {
        let dir = tempfile::tempdir().unwrap();
        let subdir = dir.path().join("sub");
        std::fs::create_dir(&subdir).unwrap();

        let non_canonical = dir.path().join("sub").join("..").join("sub");
        let config = SystemdTimerMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            timer_dirs: vec![non_canonical],
            min_interval_warn_seconds: 60,
        };
        let mut module = SystemdTimerMonitorModule::new(config, None);
        assert!(module.init().is_ok());
        assert_eq!(module.config.timer_dirs.len(), 1);
        assert!(!module.config.timer_dirs[0].to_string_lossy().contains(".."));
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.timer"), "[Timer]\nOnBootSec=5min").unwrap();

        let config = SystemdTimerMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            timer_dirs: vec![dir.path().to_path_buf()],
            min_interval_warn_seconds: 60,
        };
        let mut module = SystemdTimerMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan_with_files() {
        let dir = tempfile::tempdir().unwrap();
        let timer1 = dir.path().join("a.timer");
        let timer2 = dir.path().join("b.timer");
        let service1 = dir.path().join("a.service");
        let service2 = dir.path().join("b.service");
        std::fs::write(&timer1, "[Timer]\nOnBootSec=5min").unwrap();
        std::fs::write(&timer2, "[Timer]\nOnUnitActiveSec=1h").unwrap();
        std::fs::write(&service1, "[Service]\nExecStart=/bin/true").unwrap();
        std::fs::write(&service2, "[Service]\nExecStart=/bin/true").unwrap();

        let config = SystemdTimerMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            timer_dirs: vec![dir.path().to_path_buf()],
            min_interval_warn_seconds: 60,
        };
        let mut module = SystemdTimerMonitorModule::new(config, None);
        module.init().unwrap();

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("2件"));
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let config = SystemdTimerMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            timer_dirs: vec![],
            min_interval_warn_seconds: 60,
        };
        let module = SystemdTimerMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[tokio::test]
    async fn test_initial_scan_detects_suspicious() {
        let dir = tempfile::tempdir().unwrap();
        // 短いインターバル + サービスファイルなし
        std::fs::write(dir.path().join("suspicious.timer"), "[Timer]\nOnBootSec=5s").unwrap();

        let config = SystemdTimerMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            timer_dirs: vec![dir.path().to_path_buf()],
            min_interval_warn_seconds: 60,
        };
        let mut module = SystemdTimerMonitorModule::new(config, None);
        module.init().unwrap();

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        // 短いインターバル + サービスなし = 2件
        assert_eq!(result.issues_found, 2);
    }

    #[test]
    fn test_change_report_has_changes_empty() {
        let report = ChangeReport {
            modified: vec![],
            added: vec![],
            removed: vec![],
        };
        assert!(!report.has_changes());
    }

    #[test]
    fn test_suspicious_report_has_issues_empty() {
        let report = SuspiciousReport {
            short_interval: vec![],
            missing_service: vec![],
        };
        assert!(!report.has_issues());
    }

    #[test]
    fn test_parse_systemd_time_span_milliseconds() {
        assert_eq!(parse_systemd_time_span("500ms"), Some(0));
        assert_eq!(parse_systemd_time_span("100msec"), Some(0));
    }

    #[test]
    fn test_parse_systemd_time_span_microseconds() {
        assert_eq!(parse_systemd_time_span("500us"), Some(0));
        assert_eq!(parse_systemd_time_span("100usec"), Some(0));
    }
}
