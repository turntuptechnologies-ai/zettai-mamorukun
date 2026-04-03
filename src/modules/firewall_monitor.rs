//! ファイアウォールルール監視モジュール
//!
//! procfs 上のファイアウォール関連ファイルを定期的にスキャンし、SHA-256 ハッシュベースで変更を検知する。
//!
//! 検知対象:
//! - ファイアウォールルールの変更（iptables/ip6tables）
//! - 新たに出現したファイアウォール関連ファイル
//! - 削除されたファイアウォール関連ファイル

use crate::config::FirewallMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// ファイアウォールルール変更レポート
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

/// ファイアウォールルール監視モジュール
///
/// procfs 上のファイアウォール関連ファイルを定期スキャンし、ベースラインとの差分を検知する。
pub struct FirewallMonitorModule {
    config: FirewallMonitorConfig,
    event_bus: Option<EventBus>,
    baseline: Option<HashMap<PathBuf, String>>,
    cancel_token: CancellationToken,
}

impl FirewallMonitorModule {
    /// 新しいファイアウォールルール監視モジュールを作成する
    pub fn new(config: FirewallMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            event_bus,
            baseline: None,
            cancel_token: CancellationToken::new(),
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// 監視対象パスをスキャンし、各ファイルの SHA-256 ハッシュを返す
    fn scan_files(watch_paths: &[PathBuf]) -> HashMap<PathBuf, String> {
        let mut result = HashMap::new();
        for path in watch_paths {
            if path.is_file() {
                match compute_hash(path) {
                    Ok(hash) => {
                        result.insert(path.clone(), hash);
                    }
                    Err(e) => {
                        tracing::debug!(path = %path.display(), error = %e, "ファイアウォール関連ファイルの読み取りに失敗しました。スキャンを継続します");
                    }
                }
            } else {
                tracing::debug!(path = %path.display(), "ファイアウォール関連ファイルが存在しません。スキップします");
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
}

/// ファイルの SHA-256 ハッシュを計算する
fn compute_hash(path: &PathBuf) -> Result<String, AppError> {
    let data = std::fs::read(path).map_err(|e| AppError::FileIo {
        path: path.clone(),
        source: e,
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}

impl Module for FirewallMonitorModule {
    fn name(&self) -> &str {
        "firewall_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            watch_paths = ?self.config.watch_paths,
            scan_interval_secs = self.config.scan_interval_secs,
            "ファイアウォールルール監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        // 初回スキャンでベースライン作成
        let baseline = Self::scan_files(&self.config.watch_paths);
        tracing::info!(
            file_count = baseline.len(),
            "ベースラインスキャンが完了しました"
        );

        self.baseline = Some(baseline);

        // baseline の所有権をタスクに移動
        let mut baseline = self.baseline.take().ok_or_else(|| AppError::ModuleConfig {
            message: "ベースラインが未初期化です".to_string(),
        })?;

        let watch_paths = self.config.watch_paths.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ファイアウォールルール監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = FirewallMonitorModule::scan_files(&watch_paths);
                        let report = FirewallMonitorModule::detect_changes(&baseline, &current);

                        if report.has_changes() {
                            for path in &report.modified {
                                tracing::warn!(path = %path.display(), change = "modified", "ファイアウォールルールの変更を検知しました");
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "firewall_modified",
                                            Severity::Warning,
                                            "firewall_monitor",
                                            format!("ファイアウォールルールの変更を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            for path in &report.added {
                                tracing::warn!(path = %path.display(), change = "added", "ファイアウォールルール関連ファイルの追加を検知しました");
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "firewall_added",
                                            Severity::Warning,
                                            "firewall_monitor",
                                            format!("ファイアウォールルール関連ファイルの追加を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            for path in &report.removed {
                                tracing::warn!(path = %path.display(), change = "removed", "ファイアウォールルール関連ファイルの削除を検知しました");
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "firewall_removed",
                                            Severity::Warning,
                                            "firewall_monitor",
                                            format!("ファイアウォールルール関連ファイルの削除を検知しました: {}", path.display()),
                                        )
                                        .with_details(path.display().to_string()),
                                    );
                                }
                            }
                            // ベースラインを更新
                            baseline = current;
                        } else {
                            tracing::debug!("ファイアウォールルールの変更はありません");
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let files = Self::scan_files(&self.config.watch_paths);
        let items_scanned = files.len();
        let snapshot: BTreeMap<String, String> = files
            .iter()
            .map(|(path, hash)| (path.display().to_string(), hash.clone()))
            .collect();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!(
                "ファイアウォール関連ファイル {}件をスキャンしました",
                items_scanned
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
        let hash = compute_hash(&tmpfile.path().to_path_buf()).unwrap();
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_hash_nonexistent() {
        let result = compute_hash(&PathBuf::from("/tmp/nonexistent-file-zettai-firewall-test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_files_with_single_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "ip_tables").unwrap();
        let path = tmpfile.path().to_path_buf();

        let watch_paths = vec![path.clone()];
        let result = FirewallMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&path));
    }

    #[test]
    fn test_scan_files_empty() {
        let watch_paths: Vec<PathBuf> = vec![];
        let result = FirewallMonitorModule::scan_files(&watch_paths);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_files_nonexistent_skipped() {
        let watch_paths = vec![PathBuf::from("/proc/net/nonexistent_zettai_test")];
        let result = FirewallMonitorModule::scan_files(&watch_paths);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_files_multiple() {
        let mut tmpfile1 = tempfile::NamedTempFile::new().unwrap();
        let mut tmpfile2 = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile1, "content1").unwrap();
        write!(tmpfile2, "content2").unwrap();

        let watch_paths = vec![tmpfile1.path().to_path_buf(), tmpfile2.path().to_path_buf()];
        let result = FirewallMonitorModule::scan_files(&watch_paths);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_detect_changes_no_changes() {
        let mut baseline = HashMap::new();
        baseline.insert(
            PathBuf::from("/proc/net/ip_tables_names"),
            "hash1".to_string(),
        );

        let current = baseline.clone();
        let report = FirewallMonitorModule::detect_changes(&baseline, &current);
        assert!(!report.has_changes());
    }

    #[test]
    fn test_detect_changes_modified() {
        let mut baseline = HashMap::new();
        baseline.insert(
            PathBuf::from("/proc/net/ip_tables_names"),
            "hash1".to_string(),
        );

        let mut current = HashMap::new();
        current.insert(
            PathBuf::from("/proc/net/ip_tables_names"),
            "hash2".to_string(),
        );

        let report = FirewallMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(report.modified.len(), 1);
        assert!(report.added.is_empty());
        assert!(report.removed.is_empty());
    }

    #[test]
    fn test_detect_changes_added() {
        let baseline = HashMap::new();
        let mut current = HashMap::new();
        current.insert(
            PathBuf::from("/proc/net/ip_tables_names"),
            "hash1".to_string(),
        );

        let report = FirewallMonitorModule::detect_changes(&baseline, &current);
        assert!(report.modified.is_empty());
        assert_eq!(report.added.len(), 1);
        assert!(report.removed.is_empty());
    }

    #[test]
    fn test_detect_changes_removed() {
        let mut baseline = HashMap::new();
        baseline.insert(
            PathBuf::from("/proc/net/ip_tables_names"),
            "hash1".to_string(),
        );

        let current = HashMap::new();
        let report = FirewallMonitorModule::detect_changes(&baseline, &current);
        assert!(report.modified.is_empty());
        assert!(report.added.is_empty());
        assert_eq!(report.removed.len(), 1);
    }

    #[test]
    fn test_detect_changes_combined() {
        let mut baseline = HashMap::new();
        baseline.insert(
            PathBuf::from("/proc/net/ip_tables_names"),
            "hash1".to_string(),
        );
        baseline.insert(
            PathBuf::from("/proc/net/ip_tables_targets"),
            "hash2".to_string(),
        );
        baseline.insert(
            PathBuf::from("/proc/net/ip_tables_matches"),
            "hash3".to_string(),
        );

        let mut current = HashMap::new();
        current.insert(
            PathBuf::from("/proc/net/ip_tables_names"),
            "hash1".to_string(),
        );
        current.insert(
            PathBuf::from("/proc/net/ip_tables_matches"),
            "hash_changed".to_string(),
        );
        current.insert(
            PathBuf::from("/proc/net/ip6_tables_names"),
            "hash4".to_string(),
        );

        let report = FirewallMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(report.modified.len(), 1);
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.removed.len(), 1);
        assert!(
            report
                .modified
                .contains(&PathBuf::from("/proc/net/ip_tables_matches"))
        );
        assert!(
            report
                .added
                .contains(&PathBuf::from("/proc/net/ip6_tables_names"))
        );
        assert!(
            report
                .removed
                .contains(&PathBuf::from("/proc/net/ip_tables_targets"))
        );
    }

    #[test]
    fn test_init_zero_interval() {
        let config = FirewallMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            watch_paths: vec![],
        };
        let mut module = FirewallMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = FirewallMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![PathBuf::from("/proc/net/ip_tables_names")],
        };
        let mut module = FirewallMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "ip_tables").unwrap();

        let config = FirewallMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            watch_paths: vec![tmpfile.path().to_path_buf()],
        };
        let mut module = FirewallMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
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

    #[tokio::test]
    async fn test_initial_scan_with_files() {
        let mut tmpfile1 = tempfile::NamedTempFile::new().unwrap();
        let mut tmpfile2 = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile1, "content1").unwrap();
        write!(tmpfile2, "content2").unwrap();

        let config = FirewallMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![tmpfile1.path().to_path_buf(), tmpfile2.path().to_path_buf()],
        };
        let mut module = FirewallMonitorModule::new(config, None);
        module.init().unwrap();

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("2件"));
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let config = FirewallMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            watch_paths: vec![],
        };
        let module = FirewallMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }
}
