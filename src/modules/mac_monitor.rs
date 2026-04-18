//! SELinux / AppArmor 監視モジュール
//!
//! Mandatory Access Control (MAC) の設定ファイルを定期的にスキャンし、
//! SHA-256 ハッシュベースで変更を検知する。
//!
//! 検知対象:
//! - SELinux 設定ファイル・ポリシーの変更（改ざん検知）
//! - SELinux enforce モードの弱体化（Critical）
//! - AppArmor 設定ファイルの変更（改ざん検知）
//! - AppArmor プロファイルの弱体化・削除（Critical）

use crate::config::MacMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::core::module_stats::ModuleStatsHandle;
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// モジュール識別子（`ModuleStats` に登録する統計上のモジュール名）
pub(crate) const MODULE_STATS_NAME: &str = "SELinux / AppArmor 監視モジュール";

/// MAC スナップショット — スキャン時点の状態を保持する
struct MacSnapshot {
    /// 監視対象ファイルのハッシュ (パス → SHA-256)
    file_hashes: HashMap<PathBuf, String>,
    /// SELinux enforce モードの値 ("0" or "1")
    selinux_enforce: Option<String>,
    /// AppArmor プロファイルの状態 (プロファイル名 → モード)
    apparmor_profiles: HashMap<String, String>,
}

/// SELinux / AppArmor 監視モジュール
///
/// MAC 関連の設定ファイルを定期スキャンし、ベースラインとの差分を検知する。
pub struct MacMonitorModule {
    config: MacMonitorConfig,
    event_bus: Option<EventBus>,
    cancel_token: CancellationToken,
    stats_handle: Option<ModuleStatsHandle>,
}

impl MacMonitorModule {
    /// 新しい SELinux / AppArmor 監視モジュールを作成する
    pub fn new(config: MacMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            event_bus,
            cancel_token: CancellationToken::new(),
            stats_handle: None,
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// 設定に基づいて全監視対象をスキャンし、スナップショットを返す
    fn scan(config: &MacMonitorConfig) -> MacSnapshot {
        let file_hashes = scan_file_hashes(config);
        let selinux_enforce = read_selinux_enforce(&config.selinux_enforce_path);
        let apparmor_profiles = parse_apparmor_profiles(&config.apparmor_profiles_path);

        MacSnapshot {
            file_hashes,
            selinux_enforce,
            apparmor_profiles,
        }
    }

    /// ベースラインと現在のスナップショットを比較し、変更を検知してイベントを発行する
    fn detect_and_report(
        baseline: &MacSnapshot,
        current: &MacSnapshot,
        event_bus: &Option<EventBus>,
    ) {
        // ファイルハッシュの比較
        detect_file_changes(baseline, current, event_bus);

        // SELinux enforce モードの変更検知
        detect_selinux_enforce_changes(baseline, current, event_bus);

        // AppArmor プロファイルの変更検知
        detect_apparmor_changes(baseline, current, event_bus);
    }
}

/// 監視対象のすべてのファイル・ディレクトリからハッシュを収集する
fn scan_file_hashes(config: &MacMonitorConfig) -> HashMap<PathBuf, String> {
    let mut result = HashMap::new();

    // SELinux 設定ファイル
    for path in &config.selinux_config_paths {
        collect_hashes(path, &mut result);
    }

    // SELinux ポリシーディレクトリ
    for path in &config.selinux_policy_dirs {
        collect_hashes(path, &mut result);
    }

    // AppArmor 設定パス
    for path in &config.apparmor_config_paths {
        collect_hashes(path, &mut result);
    }

    result
}

/// パスがファイルならハッシュを計算し、ディレクトリなら再帰的にファイルを収集する
fn collect_hashes(path: &Path, result: &mut HashMap<PathBuf, String>) {
    if path.is_file() {
        match compute_hash(path) {
            Ok(hash) => {
                result.insert(path.to_path_buf(), hash);
            }
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "MAC設定ファイルの読み取りに失敗しました。スキャンを継続します");
            }
        }
    } else if path.is_dir() {
        match std::fs::read_dir(path) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if entry_path.is_file() {
                        match compute_hash(&entry_path) {
                            Ok(hash) => {
                                result.insert(entry_path, hash);
                            }
                            Err(e) => {
                                tracing::debug!(path = %entry.path().display(), error = %e, "MAC設定ファイルの読み取りに失敗しました。スキャンを継続します");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "ディレクトリの読み取りに失敗しました。スキップします");
            }
        }
    } else {
        tracing::debug!(path = %path.display(), "MAC設定パスが存在しません。スキップします");
    }
}

/// ファイルの SHA-256 ハッシュを計算する
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

/// SELinux enforce ファイルを読み取り、値を返す
fn read_selinux_enforce(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(content) => Some(content.trim().to_string()),
        Err(_) => {
            tracing::debug!(path = %path.display(), "SELinux enforce ファイルが読み取れません（SELinux が無効の可能性）");
            None
        }
    }
}

/// AppArmor profiles ファイルをパースし、プロファイル名とモードのマップを返す
///
/// 形式: `profile_name (mode)`
fn parse_apparmor_profiles(path: &Path) -> HashMap<String, String> {
    let mut profiles = HashMap::new();
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            tracing::debug!(path = %path.display(), "AppArmor profiles ファイルが読み取れません（AppArmor が無効の可能性）");
            return profiles;
        }
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // 形式: "profile_name (mode)"
        if let Some(paren_start) = line.rfind('(')
            && let Some(paren_end) = line.rfind(')')
            && paren_start < paren_end
        {
            let name = line[..paren_start].trim().to_string();
            let mode = line[paren_start + 1..paren_end].trim().to_string();
            if !name.is_empty() && !mode.is_empty() {
                profiles.insert(name, mode);
            }
        }
    }

    profiles
}

/// ファイルハッシュの変更を検知してイベントを発行する
fn detect_file_changes(
    baseline: &MacSnapshot,
    current: &MacSnapshot,
    event_bus: &Option<EventBus>,
) {
    // 変更・追加の検知
    for (path, current_hash) in &current.file_hashes {
        let path_str = path.display().to_string();
        let is_selinux_config = path_str.contains("selinux");

        match baseline.file_hashes.get(path) {
            Some(baseline_hash) if baseline_hash != current_hash => {
                let event_type = if is_selinux_config {
                    "mac_selinux_config_modified"
                } else {
                    "mac_apparmor_config_modified"
                };
                tracing::warn!(path = %path.display(), change = "modified", "MAC設定ファイルの変更を検知しました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            event_type,
                            Severity::Warning,
                            "mac_monitor",
                            format!("MAC設定ファイルの変更を検知しました: {}", path.display()),
                        )
                        .with_details(path.display().to_string()),
                    );
                }
            }
            None => {
                let event_type = if is_selinux_config {
                    "mac_selinux_config_added"
                } else {
                    "mac_apparmor_config_added"
                };
                tracing::warn!(path = %path.display(), change = "added", "MAC設定ファイルの追加を検知しました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            event_type,
                            Severity::Warning,
                            "mac_monitor",
                            format!("MAC設定ファイルの追加を検知しました: {}", path.display()),
                        )
                        .with_details(path.display().to_string()),
                    );
                }
            }
            _ => {}
        }
    }

    // 削除の検知
    for path in baseline.file_hashes.keys() {
        if !current.file_hashes.contains_key(path) {
            let path_str = path.display().to_string();
            let is_selinux_config = path_str.contains("selinux");
            let event_type = if is_selinux_config {
                "mac_selinux_config_removed"
            } else {
                "mac_apparmor_config_removed"
            };
            tracing::warn!(path = %path.display(), change = "removed", "MAC設定ファイルの削除を検知しました");
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        event_type,
                        Severity::Warning,
                        "mac_monitor",
                        format!("MAC設定ファイルの削除を検知しました: {}", path.display()),
                    )
                    .with_details(path.display().to_string()),
                );
            }
        }
    }
}

/// SELinux enforce モードの変更を検知する
fn detect_selinux_enforce_changes(
    baseline: &MacSnapshot,
    current: &MacSnapshot,
    event_bus: &Option<EventBus>,
) {
    match (&baseline.selinux_enforce, &current.selinux_enforce) {
        // enforce → permissive (1 → 0): Critical
        (Some(old), Some(new)) if old == "1" && new == "0" => {
            tracing::error!("SELinux が enforce モードから permissive モードに変更されました");
            if let Some(bus) = event_bus {
                bus.publish(SecurityEvent::new(
                    "mac_selinux_mode_weakened",
                    Severity::Critical,
                    "mac_monitor",
                    "SELinux が enforce モードから permissive モードに変更されました".to_string(),
                ));
            }
        }
        // enforce が読めなくなった（SELinux が無効化された可能性）
        (Some(_), None) => {
            tracing::error!(
                "SELinux が無効化された可能性があります（enforce ファイルが読み取れなくなりました）"
            );
            if let Some(bus) = event_bus {
                bus.publish(SecurityEvent::new(
                    "mac_selinux_disabled",
                    Severity::Critical,
                    "mac_monitor",
                    "SELinux が無効化された可能性があります".to_string(),
                ));
            }
        }
        _ => {}
    }
}

/// AppArmor プロファイルの変更を検知する
fn detect_apparmor_changes(
    baseline: &MacSnapshot,
    current: &MacSnapshot,
    event_bus: &Option<EventBus>,
) {
    // プロファイルの弱体化・変更の検知
    for (name, old_mode) in &baseline.apparmor_profiles {
        match current.apparmor_profiles.get(name) {
            Some(new_mode)
                if old_mode != new_mode
                // enforce → complain/unconfined は Critical
                && old_mode == "enforce" && (new_mode == "complain" || new_mode == "unconfined") =>
            {
                tracing::error!(
                    profile = %name,
                    old_mode = %old_mode,
                    new_mode = %new_mode,
                    "AppArmor プロファイルが弱体化されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "mac_apparmor_profile_weakened",
                            Severity::Critical,
                            "mac_monitor",
                            format!(
                                "AppArmor プロファイル '{}' が {} から {} に変更されました",
                                name, old_mode, new_mode
                            ),
                        )
                        .with_details(format!("{}: {} -> {}", name, old_mode, new_mode)),
                    );
                }
            }
            None => {
                // プロファイルが削除された: Critical
                tracing::error!(profile = %name, "AppArmor プロファイルが削除されました");
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "mac_apparmor_profile_removed",
                            Severity::Critical,
                            "mac_monitor",
                            format!("AppArmor プロファイル '{}' が削除されました", name),
                        )
                        .with_details(name.clone()),
                    );
                }
            }
            _ => {}
        }
    }

    // 新規プロファイルの検知
    for name in current.apparmor_profiles.keys() {
        if !baseline.apparmor_profiles.contains_key(name) {
            let mode = &current.apparmor_profiles[name];
            tracing::warn!(
                profile = %name,
                mode = %mode,
                "AppArmor プロファイルが追加されました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "mac_apparmor_profile_added",
                        Severity::Warning,
                        "mac_monitor",
                        format!(
                            "AppArmor プロファイル '{}' が追加されました (モード: {})",
                            name, mode
                        ),
                    )
                    .with_details(format!("{}: {}", name, mode)),
                );
            }
        }
    }
}

impl Module for MacMonitorModule {
    fn name(&self) -> &str {
        "mac_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            selinux_config_paths = ?self.config.selinux_config_paths,
            selinux_policy_dirs = ?self.config.selinux_policy_dirs,
            selinux_enforce_path = %self.config.selinux_enforce_path.display(),
            apparmor_config_paths = ?self.config.apparmor_config_paths,
            apparmor_profiles_path = %self.config.apparmor_profiles_path.display(),
            scan_interval_secs = self.config.scan_interval_secs,
            "SELinux / AppArmor 監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        // 初回スキャンでベースライン作成
        let baseline = Self::scan(&self.config);
        tracing::info!(
            file_count = baseline.file_hashes.len(),
            selinux_enforce = ?baseline.selinux_enforce,
            apparmor_profiles = baseline.apparmor_profiles.len(),
            "ベースラインスキャンが完了しました"
        );

        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let stats_handle = self.stats_handle.clone();

        let handle = tokio::spawn(async move {
            let mut baseline = baseline;
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(config.scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("SELinux / AppArmor 監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let scan_start = std::time::Instant::now();
                        let current = MacMonitorModule::scan(&config);
                        MacMonitorModule::detect_and_report(&baseline, &current, &event_bus);
                        let scan_elapsed = scan_start.elapsed();
                        if let Some(ref handle) = stats_handle {
                            handle.record_scan_duration(MODULE_STATS_NAME, scan_elapsed);
                        }
                        // ベースラインを更新
                        baseline = current;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let snapshot_data = Self::scan(&self.config);

        let mut items_scanned = snapshot_data.file_hashes.len();
        let mut snapshot: BTreeMap<String, String> = BTreeMap::new();

        // ファイルハッシュ
        for (path, hash) in &snapshot_data.file_hashes {
            snapshot.insert(format!("file:{}", path.display()), hash.clone());
        }

        // SELinux enforce
        if let Some(ref enforce) = snapshot_data.selinux_enforce {
            snapshot.insert("selinux_enforce".to_string(), enforce.clone());
            items_scanned += 1;
        }

        // AppArmor プロファイル
        for (name, mode) in &snapshot_data.apparmor_profiles {
            snapshot.insert(format!("apparmor:{}", name), mode.clone());
            items_scanned += 1;
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!(
                "MAC設定ファイル {}件、SELinux enforce: {}、AppArmor プロファイル {}件をスキャンしました",
                snapshot_data.file_hashes.len(),
                snapshot_data.selinux_enforce.as_deref().unwrap_or("N/A"),
                snapshot_data.apparmor_profiles.len()
            ),
            snapshot,
        })
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }

    fn set_module_stats(&mut self, handle: ModuleStatsHandle) {
        self.stats_handle = Some(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_compute_hash() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "SELINUX=enforcing").unwrap();
        let hash = compute_hash(tmpfile.path()).unwrap();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 は 64 文字の hex
    }

    #[test]
    fn test_compute_hash_deterministic() {
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
        let result = compute_hash(Path::new("/tmp/nonexistent-file-zettai-mac-test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_file_hashes_with_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let file1 = dir.path().join("config");
        let file2 = dir.path().join("policy");
        std::fs::write(&file1, "SELINUX=enforcing").unwrap();
        std::fs::write(&file2, "policy data").unwrap();

        let config = MacMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            selinux_config_paths: vec![file1],
            selinux_policy_dirs: vec![dir.path().to_path_buf()],
            selinux_enforce_path: PathBuf::from("/nonexistent"),
            apparmor_config_paths: vec![],
            apparmor_profiles_path: PathBuf::from("/nonexistent"),
        };
        let result = scan_file_hashes(&config);
        // file1 は selinux_config_paths で直接、file2 は selinux_policy_dirs のディレクトリスキャンで拾われる
        // ただし dir 内には config と policy があるので、config は重複する可能性がある
        assert!(result.len() >= 2);
    }

    #[test]
    fn test_scan_file_hashes_empty() {
        let config = MacMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            selinux_config_paths: vec![],
            selinux_policy_dirs: vec![],
            selinux_enforce_path: PathBuf::from("/nonexistent"),
            apparmor_config_paths: vec![],
            apparmor_profiles_path: PathBuf::from("/nonexistent"),
        };
        let result = scan_file_hashes(&config);
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_file_hashes_nonexistent_skipped() {
        let config = MacMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            selinux_config_paths: vec![PathBuf::from("/tmp/nonexistent_zettai_mac_test")],
            selinux_policy_dirs: vec![],
            selinux_enforce_path: PathBuf::from("/nonexistent"),
            apparmor_config_paths: vec![],
            apparmor_profiles_path: PathBuf::from("/nonexistent"),
        };
        let result = scan_file_hashes(&config);
        assert!(result.is_empty());
    }

    #[test]
    fn test_read_selinux_enforce_with_value() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "1").unwrap();
        let result = read_selinux_enforce(tmpfile.path());
        assert_eq!(result, Some("1".to_string()));
    }

    #[test]
    fn test_read_selinux_enforce_zero() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "0").unwrap();
        let result = read_selinux_enforce(tmpfile.path());
        assert_eq!(result, Some("0".to_string()));
    }

    #[test]
    fn test_read_selinux_enforce_nonexistent() {
        let result = read_selinux_enforce(Path::new("/tmp/nonexistent_selinux_enforce"));
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_apparmor_profiles_with_entries() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            "/usr/sbin/ntpd (enforce)\n/usr/bin/firefox (complain)\n/usr/sbin/sshd (enforce)\n"
        )
        .unwrap();
        let result = parse_apparmor_profiles(tmpfile.path());
        assert_eq!(result.len(), 3);
        assert_eq!(result.get("/usr/sbin/ntpd"), Some(&"enforce".to_string()));
        assert_eq!(
            result.get("/usr/bin/firefox"),
            Some(&"complain".to_string())
        );
        assert_eq!(result.get("/usr/sbin/sshd"), Some(&"enforce".to_string()));
    }

    #[test]
    fn test_parse_apparmor_profiles_empty_file() {
        let tmpfile = tempfile::NamedTempFile::new().unwrap();
        let result = parse_apparmor_profiles(tmpfile.path());
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_apparmor_profiles_nonexistent() {
        let result = parse_apparmor_profiles(Path::new("/tmp/nonexistent_apparmor_profiles"));
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_apparmor_profiles_malformed_lines() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "no parens here\n(only mode)\n").unwrap();
        let result = parse_apparmor_profiles(tmpfile.path());
        assert!(result.is_empty());
    }

    #[test]
    fn test_detect_and_report_no_changes() {
        let baseline = MacSnapshot {
            file_hashes: HashMap::from([(PathBuf::from("/etc/selinux/config"), "hash1".into())]),
            selinux_enforce: Some("1".into()),
            apparmor_profiles: HashMap::from([("/usr/sbin/sshd".into(), "enforce".into())]),
        };
        let current = MacSnapshot {
            file_hashes: HashMap::from([(PathBuf::from("/etc/selinux/config"), "hash1".into())]),
            selinux_enforce: Some("1".into()),
            apparmor_profiles: HashMap::from([("/usr/sbin/sshd".into(), "enforce".into())]),
        };
        // No panic, no events (event_bus is None)
        MacMonitorModule::detect_and_report(&baseline, &current, &None);
    }

    #[test]
    fn test_detect_and_report_file_modified() {
        let baseline = MacSnapshot {
            file_hashes: HashMap::from([(PathBuf::from("/etc/selinux/config"), "hash1".into())]),
            selinux_enforce: None,
            apparmor_profiles: HashMap::new(),
        };
        let current = MacSnapshot {
            file_hashes: HashMap::from([(PathBuf::from("/etc/selinux/config"), "hash2".into())]),
            selinux_enforce: None,
            apparmor_profiles: HashMap::new(),
        };
        // Should not panic with None event bus
        MacMonitorModule::detect_and_report(&baseline, &current, &None);
    }

    #[test]
    fn test_detect_and_report_file_added() {
        let baseline = MacSnapshot {
            file_hashes: HashMap::new(),
            selinux_enforce: None,
            apparmor_profiles: HashMap::new(),
        };
        let current = MacSnapshot {
            file_hashes: HashMap::from([(
                PathBuf::from("/etc/apparmor.d/usr.bin.foo"),
                "hash1".into(),
            )]),
            selinux_enforce: None,
            apparmor_profiles: HashMap::new(),
        };
        MacMonitorModule::detect_and_report(&baseline, &current, &None);
    }

    #[test]
    fn test_detect_and_report_file_removed() {
        let baseline = MacSnapshot {
            file_hashes: HashMap::from([(PathBuf::from("/etc/selinux/config"), "hash1".into())]),
            selinux_enforce: None,
            apparmor_profiles: HashMap::new(),
        };
        let current = MacSnapshot {
            file_hashes: HashMap::new(),
            selinux_enforce: None,
            apparmor_profiles: HashMap::new(),
        };
        MacMonitorModule::detect_and_report(&baseline, &current, &None);
    }

    #[test]
    fn test_detect_and_report_selinux_weakened() {
        let baseline = MacSnapshot {
            file_hashes: HashMap::new(),
            selinux_enforce: Some("1".into()),
            apparmor_profiles: HashMap::new(),
        };
        let current = MacSnapshot {
            file_hashes: HashMap::new(),
            selinux_enforce: Some("0".into()),
            apparmor_profiles: HashMap::new(),
        };
        MacMonitorModule::detect_and_report(&baseline, &current, &None);
    }

    #[test]
    fn test_detect_and_report_selinux_disabled() {
        let baseline = MacSnapshot {
            file_hashes: HashMap::new(),
            selinux_enforce: Some("1".into()),
            apparmor_profiles: HashMap::new(),
        };
        let current = MacSnapshot {
            file_hashes: HashMap::new(),
            selinux_enforce: None,
            apparmor_profiles: HashMap::new(),
        };
        MacMonitorModule::detect_and_report(&baseline, &current, &None);
    }

    #[test]
    fn test_detect_and_report_apparmor_weakened() {
        let baseline = MacSnapshot {
            file_hashes: HashMap::new(),
            selinux_enforce: None,
            apparmor_profiles: HashMap::from([("/usr/sbin/sshd".into(), "enforce".into())]),
        };
        let current = MacSnapshot {
            file_hashes: HashMap::new(),
            selinux_enforce: None,
            apparmor_profiles: HashMap::from([("/usr/sbin/sshd".into(), "complain".into())]),
        };
        MacMonitorModule::detect_and_report(&baseline, &current, &None);
    }

    #[test]
    fn test_detect_and_report_apparmor_removed() {
        let baseline = MacSnapshot {
            file_hashes: HashMap::new(),
            selinux_enforce: None,
            apparmor_profiles: HashMap::from([("/usr/sbin/sshd".into(), "enforce".into())]),
        };
        let current = MacSnapshot {
            file_hashes: HashMap::new(),
            selinux_enforce: None,
            apparmor_profiles: HashMap::new(),
        };
        MacMonitorModule::detect_and_report(&baseline, &current, &None);
    }

    #[test]
    fn test_detect_and_report_apparmor_added() {
        let baseline = MacSnapshot {
            file_hashes: HashMap::new(),
            selinux_enforce: None,
            apparmor_profiles: HashMap::new(),
        };
        let current = MacSnapshot {
            file_hashes: HashMap::new(),
            selinux_enforce: None,
            apparmor_profiles: HashMap::from([("/usr/sbin/sshd".into(), "enforce".into())]),
        };
        MacMonitorModule::detect_and_report(&baseline, &current, &None);
    }

    #[test]
    fn test_init_zero_interval() {
        let config = MacMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            ..MacMonitorConfig::default()
        };
        let mut module = MacMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = MacMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            ..MacMonitorConfig::default()
        };
        let mut module = MacMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = MacMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            ..MacMonitorConfig::default()
        };
        let mut module = MacMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let dir = tempfile::TempDir::new().unwrap();
        let file1 = dir.path().join("config");
        std::fs::write(&file1, "SELINUX=enforcing").unwrap();

        let config = MacMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            selinux_config_paths: vec![file1],
            selinux_policy_dirs: vec![],
            selinux_enforce_path: PathBuf::from("/nonexistent"),
            apparmor_config_paths: vec![],
            apparmor_profiles_path: PathBuf::from("/nonexistent"),
        };
        let module = MacMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("1件"));
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let config = MacMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            selinux_config_paths: vec![],
            selinux_policy_dirs: vec![],
            selinux_enforce_path: PathBuf::from("/nonexistent"),
            apparmor_config_paths: vec![],
            apparmor_profiles_path: PathBuf::from("/nonexistent"),
        };
        let module = MacMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
    }

    #[tokio::test]
    async fn test_initial_scan_with_selinux_enforce() {
        let mut enforce_file = tempfile::NamedTempFile::new().unwrap();
        write!(enforce_file, "1").unwrap();

        let config = MacMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            selinux_config_paths: vec![],
            selinux_policy_dirs: vec![],
            selinux_enforce_path: enforce_file.path().to_path_buf(),
            apparmor_config_paths: vec![],
            apparmor_profiles_path: PathBuf::from("/nonexistent"),
        };
        let module = MacMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1); // selinux_enforce のみ
        assert!(result.snapshot.contains_key("selinux_enforce"));
        assert_eq!(
            result.snapshot.get("selinux_enforce"),
            Some(&"1".to_string())
        );
    }

    #[tokio::test]
    async fn test_initial_scan_with_apparmor_profiles() {
        let mut profiles_file = tempfile::NamedTempFile::new().unwrap();
        write!(
            profiles_file,
            "/usr/sbin/sshd (enforce)\n/usr/bin/firefox (complain)\n"
        )
        .unwrap();

        let config = MacMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            selinux_config_paths: vec![],
            selinux_policy_dirs: vec![],
            selinux_enforce_path: PathBuf::from("/nonexistent"),
            apparmor_config_paths: vec![],
            apparmor_profiles_path: profiles_file.path().to_path_buf(),
        };
        let module = MacMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 2); // 2 profiles
        assert_eq!(
            result.snapshot.get("apparmor:/usr/sbin/sshd"),
            Some(&"enforce".to_string())
        );
        assert_eq!(
            result.snapshot.get("apparmor:/usr/bin/firefox"),
            Some(&"complain".to_string())
        );
    }

    #[test]
    fn test_set_module_stats_stores_handle() {
        let config = MacMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            selinux_config_paths: vec![],
            selinux_policy_dirs: vec![],
            selinux_enforce_path: PathBuf::from("/nonexistent"),
            apparmor_config_paths: vec![],
            apparmor_profiles_path: PathBuf::from("/nonexistent"),
        };
        let mut module = MacMonitorModule::new(config, None);
        assert!(module.stats_handle.is_none());
        module.set_module_stats(ModuleStatsHandle::new());
        assert!(module.stats_handle.is_some());
    }

    #[tokio::test]
    async fn test_periodic_scan_records_scan_duration() {
        let config = MacMonitorConfig {
            enabled: true,
            scan_interval_secs: 1,
            selinux_config_paths: vec![],
            selinux_policy_dirs: vec![],
            selinux_enforce_path: PathBuf::from("/nonexistent"),
            apparmor_config_paths: vec![],
            apparmor_profiles_path: PathBuf::from("/nonexistent"),
        };
        let mut module = MacMonitorModule::new(config, None);
        module.init().unwrap();

        let stats = ModuleStatsHandle::new();
        module.set_module_stats(stats.clone());

        let handle = module.start().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
        module.stop().await.unwrap();
        let _ = handle.await;

        let s = stats.get(MODULE_STATS_NAME).expect("stats must exist");
        assert!(
            s.scan_count >= 1,
            "scan_count={} expected >= 1",
            s.scan_count
        );
    }
}
