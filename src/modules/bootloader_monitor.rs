//! ブートローダー整合性監視モジュール
//!
//! GRUB 設定ファイル（`/boot/grub/grub.cfg`、`/etc/default/grub` 等）を定期的にスキャンし、
//! 前回のスナップショットと比較してブートキット攻撃の兆候を検知する。
//!
//! 検知対象:
//! - ファイルのハッシュ変更（SHA-256）— Critical
//! - 既存ファイルの削除 — Critical
//! - 新規ファイルの出現 — Medium
//! - パーミッション・オーナーの変更 — High
//! - カーネルコマンドライン（`GRUB_CMDLINE_LINUX`）の不審な変更 — Critical/High/Warning

use crate::config::BootloaderMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

/// ファイルのスナップショット情報
#[derive(Debug, Clone, PartialEq)]
struct FileSnapshot {
    /// SHA-256 ハッシュ
    hash: String,
    /// ファイルパーミッション（モード）
    mode: u32,
    /// 所有者 UID
    uid: u32,
    /// 所有者 GID
    gid: u32,
}

/// ブートローダーファイル群のスナップショット
struct BootloaderSnapshot {
    files: HashMap<PathBuf, FileSnapshot>,
}

/// 不審なカーネルコマンドラインパラメータの種別
#[derive(Debug)]
enum SuspiciousParam {
    /// Critical: セキュリティ機構の無効化等
    Critical(String),
    /// Elevated: KASLR 無効化等
    Elevated(String),
    /// Warning: 合法利用の可能性あり
    Warning(String),
}

/// ブートローダー整合性監視モジュール
///
/// GRUB 設定ファイルを定期スキャンし、改ざんを検知する。
pub struct BootloaderMonitorModule {
    config: BootloaderMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl BootloaderMonitorModule {
    /// 新しいブートローダー整合性監視モジュールを作成する
    pub fn new(config: BootloaderMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            cancel_token: CancellationToken::new(),
            event_bus,
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// ファイルの SHA-256 ハッシュを計算する
    fn compute_hash(path: &Path) -> Option<String> {
        let content = match fs::read(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "ブートローダーファイルの読み取りに失敗しました"
                );
                return None;
            }
        };
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Some(format!("{:x}", hasher.finalize()))
    }

    /// ファイルのスナップショットを取得する
    fn snapshot_file(path: &Path) -> Option<FileSnapshot> {
        let hash = Self::compute_hash(path)?;
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "ファイルのメタデータ取得に失敗しました"
                );
                return None;
            }
        };
        Some(FileSnapshot {
            hash,
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
        })
    }

    /// EFI ディレクトリから grub.cfg ファイルを探索する
    fn find_efi_grub_configs(efi_dirs: &[PathBuf]) -> Vec<PathBuf> {
        let mut results = Vec::new();
        for dir in efi_dirs {
            if !dir.exists() {
                continue;
            }
            for entry in WalkDir::new(dir).max_depth(3).into_iter().flatten() {
                if entry.file_type().is_file() && entry.file_name() == "grub.cfg" {
                    results.push(entry.path().to_path_buf());
                }
            }
        }
        results
    }

    /// 全監視対象ファイルのパスリストを構築する
    fn collect_target_paths(grub_paths: &[PathBuf], efi_dirs: &[PathBuf]) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = grub_paths.to_vec();
        paths.extend(Self::find_efi_grub_configs(efi_dirs));
        paths.sort();
        paths.dedup();
        paths
    }

    /// スナップショットを取得する
    fn take_snapshot(grub_paths: &[PathBuf], efi_dirs: &[PathBuf]) -> BootloaderSnapshot {
        let target_paths = Self::collect_target_paths(grub_paths, efi_dirs);
        let mut files = HashMap::new();
        for path in &target_paths {
            if let Some(snap) = Self::snapshot_file(path) {
                files.insert(path.clone(), snap);
            }
        }
        BootloaderSnapshot { files }
    }

    /// `/etc/default/grub` からカーネルコマンドラインパラメータを抽出する
    fn extract_cmdline_params(content: &str) -> Vec<String> {
        let mut params = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            // GRUB_CMDLINE_LINUX= or GRUB_CMDLINE_LINUX_DEFAULT=
            if line.starts_with("GRUB_CMDLINE_LINUX")
                && let Some(value) = line.split_once('=').map(|(_, v)| v)
            {
                // 引用符を除去
                let value = value.trim().trim_matches('"').trim_matches('\'');
                for param in value.split_whitespace() {
                    params.push(param.to_string());
                }
            }
        }
        params
    }

    /// カーネルコマンドラインパラメータの不審な変更を検知する
    fn check_suspicious_params(params: &[String]) -> Vec<SuspiciousParam> {
        let mut suspicious = Vec::new();
        for param in params {
            let lower = param.to_lowercase();
            if lower.starts_with("init=")
                && lower != "init=/sbin/init"
                && lower != "init=/lib/systemd/systemd"
            {
                suspicious.push(SuspiciousParam::Critical(format!(
                    "init プロセスが変更されています: {}",
                    param
                )));
            } else if lower == "module.sig_enforce=0" {
                suspicious.push(SuspiciousParam::Critical(
                    "カーネルモジュール署名検証が無効化されています: module.sig_enforce=0"
                        .to_string(),
                ));
            } else if lower == "selinux=0" {
                suspicious.push(SuspiciousParam::Critical(
                    "SELinux が無効化されています: selinux=0".to_string(),
                ));
            } else if lower == "apparmor=0" {
                suspicious.push(SuspiciousParam::Critical(
                    "AppArmor が無効化されています: apparmor=0".to_string(),
                ));
            } else if lower == "nokaslr" {
                suspicious.push(SuspiciousParam::Elevated(
                    "KASLR が無効化されています: nokaslr".to_string(),
                ));
            } else if lower == "nosmep" || lower == "nosmap" {
                suspicious.push(SuspiciousParam::Elevated(format!(
                    "CPU セキュリティ機能が無効化されています: {}",
                    param
                )));
            } else if lower == "noapic" || lower == "nosmp" {
                suspicious.push(SuspiciousParam::Warning(format!(
                    "ハードウェア設定パラメータが設定されています: {}（合法的な使用の可能性あり）",
                    param
                )));
            }
        }
        suspicious
    }

    /// 2 つのスナップショットを比較し、変更を検知する。変更があれば true を返す。
    fn detect_changes(
        old: &BootloaderSnapshot,
        new: &BootloaderSnapshot,
        alert_on_cmdline: bool,
        grub_paths: &[PathBuf],
        efi_dirs: &[PathBuf],
        event_bus: &Option<EventBus>,
    ) -> bool {
        let mut changed = false;
        let target_paths = Self::collect_target_paths(grub_paths, efi_dirs);

        // 新規ファイル
        for path in new.files.keys() {
            if !old.files.contains_key(path) {
                changed = true;
                tracing::warn!(
                    path = %path.display(),
                    "新規ブートローダーファイルが出現しました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "bootloader_file_added",
                            Severity::Warning,
                            "bootloader_monitor",
                            "新規ブートローダーファイルが出現しました",
                        )
                        .with_details(format!("path={}", path.display())),
                    );
                }
            }
        }

        // 削除されたファイル（以前存在していたファイルが現在のターゲットに含まれるが新スナップにない）
        for path in old.files.keys() {
            if target_paths.contains(path) && !new.files.contains_key(path) {
                changed = true;
                tracing::error!(
                    path = %path.display(),
                    "CRITICAL: ブートローダーファイルが削除されました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "bootloader_file_deleted",
                            Severity::Critical,
                            "bootloader_monitor",
                            "ブートローダーファイルが削除されました",
                        )
                        .with_details(format!("path={}", path.display())),
                    );
                }
            }
        }

        // 既存ファイルの変更
        for (path, new_snap) in &new.files {
            if let Some(old_snap) = old.files.get(path) {
                // ハッシュ変更
                if old_snap.hash != new_snap.hash {
                    changed = true;
                    tracing::error!(
                        path = %path.display(),
                        old_hash = %old_snap.hash,
                        new_hash = %new_snap.hash,
                        "CRITICAL: ブートローダーファイルが改ざんされました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "bootloader_file_modified",
                                Severity::Critical,
                                "bootloader_monitor",
                                "ブートローダーファイルが改ざんされました",
                            )
                            .with_details(format!(
                                "path={}, old_hash={}, new_hash={}",
                                path.display(),
                                old_snap.hash,
                                new_snap.hash
                            )),
                        );
                    }

                    // カーネルコマンドラインチェック
                    if alert_on_cmdline {
                        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        let is_default_grub = path.ends_with("default/grub")
                            || filename == "grub"
                                && path.parent().is_some_and(|p| p.ends_with("default"));
                        if is_default_grub && let Ok(content) = fs::read_to_string(path) {
                            let params = Self::extract_cmdline_params(&content);
                            let suspicious = Self::check_suspicious_params(&params);
                            for s in &suspicious {
                                let (severity, msg) = match s {
                                    SuspiciousParam::Critical(msg) => {
                                        tracing::error!(path = %path.display(), "CRITICAL: {}", msg);
                                        (Severity::Critical, msg.as_str())
                                    }
                                    SuspiciousParam::Elevated(msg) => {
                                        tracing::warn!(path = %path.display(), "{}", msg);
                                        (Severity::Warning, msg.as_str())
                                    }
                                    SuspiciousParam::Warning(msg) => {
                                        tracing::info!(path = %path.display(), "{}", msg);
                                        (Severity::Warning, msg.as_str())
                                    }
                                };
                                if let Some(bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "bootloader_cmdline_suspicious",
                                            severity,
                                            "bootloader_monitor",
                                            msg,
                                        )
                                        .with_details(format!("path={}", path.display())),
                                    );
                                }
                            }
                        }
                    }
                }

                // パーミッション変更
                if old_snap.mode != new_snap.mode
                    || old_snap.uid != new_snap.uid
                    || old_snap.gid != new_snap.gid
                {
                    changed = true;
                    tracing::warn!(
                        path = %path.display(),
                        old_mode = format!("{:o}", old_snap.mode),
                        new_mode = format!("{:o}", new_snap.mode),
                        old_uid = old_snap.uid,
                        new_uid = new_snap.uid,
                        old_gid = old_snap.gid,
                        new_gid = new_snap.gid,
                        "ブートローダーファイルのパーミッション/オーナーが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "bootloader_permission_changed",
                                Severity::Warning,
                                "bootloader_monitor",
                                "ブートローダーファイルのパーミッション/オーナーが変更されました",
                            )
                            .with_details(format!(
                                "path={}, mode: {:o}->{:o}, uid: {}->{}, gid: {}->{}",
                                path.display(),
                                old_snap.mode,
                                new_snap.mode,
                                old_snap.uid,
                                new_snap.uid,
                                old_snap.gid,
                                new_snap.gid
                            )),
                        );
                    }
                }
            }
        }

        changed
    }
}

impl Module for BootloaderMonitorModule {
    fn name(&self) -> &str {
        "bootloader_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        let target_paths =
            Self::collect_target_paths(&self.config.grub_paths, &self.config.efi_grub_dirs);

        let existing_count = target_paths.iter().filter(|p| p.exists()).count();
        if existing_count == 0 {
            tracing::warn!("監視対象のブートローダーファイルが 1 つも見つかりません");
        }

        tracing::info!(
            target_count = target_paths.len(),
            existing_count = existing_count,
            scan_interval_secs = self.config.scan_interval_secs,
            alert_on_cmdline_changes = self.config.alert_on_cmdline_changes,
            "ブートローダー整合性監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let grub_paths = self.config.grub_paths.clone();
        let efi_dirs = self.config.efi_grub_dirs.clone();
        let interval_secs = self.config.scan_interval_secs;
        let alert_on_cmdline = self.config.alert_on_cmdline_changes;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 初回スナップショット
        let initial_snapshot = Self::take_snapshot(&grub_paths, &efi_dirs);

        if initial_snapshot.files.is_empty() {
            tracing::warn!(
                "初回スナップショットにファイルがありません。監視を開始しますが検知は限定的です"
            );
        } else {
            tracing::info!(
                file_count = initial_snapshot.files.len(),
                "初回スナップショットを取得しました"
            );
        }

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut snapshot = initial_snapshot;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ブートローダー整合性監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let new_snapshot = BootloaderMonitorModule::take_snapshot(&grub_paths, &efi_dirs);
                        let changed = BootloaderMonitorModule::detect_changes(
                            &snapshot,
                            &new_snapshot,
                            alert_on_cmdline,
                            &grub_paths,
                            &efi_dirs,
                            &event_bus,
                        );
                        if changed {
                            snapshot = new_snapshot;
                        } else {
                            tracing::debug!("ブートローダーファイルの変更はありません");
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let mut items_scanned = 0;
        let mut issues_found = 0;
        let mut snapshot_map: BTreeMap<String, String> = BTreeMap::new();

        let target_paths =
            Self::collect_target_paths(&self.config.grub_paths, &self.config.efi_grub_dirs);

        for path in &target_paths {
            if let Some(snap) = Self::snapshot_file(path) {
                items_scanned += 1;
                snapshot_map.insert(
                    path.display().to_string(),
                    format!(
                        "hash={},mode={:o},uid={},gid={}",
                        snap.hash, snap.mode, snap.uid, snap.gid
                    ),
                );
            }
        }

        // カーネルコマンドラインチェック
        if self.config.alert_on_cmdline_changes {
            for path in &target_paths {
                let is_default_grub = path.ends_with("default/grub")
                    || (path.file_name().and_then(|n| n.to_str()) == Some("grub")
                        && path.parent().is_some_and(|p| p.ends_with("default")));
                if is_default_grub && let Ok(content) = fs::read_to_string(path) {
                    let params = Self::extract_cmdline_params(&content);
                    let suspicious = Self::check_suspicious_params(&params);
                    issues_found += suspicious.len();
                }
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "ブートローダーファイル {}件をスキャンしました（問題 {}件）",
                items_scanned, issues_found
            ),
            snapshot: snapshot_map,
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
    use std::os::unix::fs::PermissionsExt;

    fn test_config(dir: &Path) -> BootloaderMonitorConfig {
        BootloaderMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
            grub_paths: vec![dir.join("grub.cfg"), dir.join("default_grub")],
            efi_grub_dirs: vec![],
            alert_on_cmdline_changes: true,
        }
    }

    #[test]
    fn test_compute_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.cfg");
        fs::write(&path, "test content").unwrap();

        let hash = BootloaderMonitorModule::compute_hash(&path);
        assert!(hash.is_some());
        let hash = hash.unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex chars
    }

    #[test]
    fn test_compute_hash_nonexistent() {
        let hash = BootloaderMonitorModule::compute_hash(Path::new("/nonexistent-file"));
        assert!(hash.is_none());
    }

    #[test]
    fn test_compute_hash_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.cfg");
        fs::write(&path, "same content").unwrap();

        let hash1 = BootloaderMonitorModule::compute_hash(&path).unwrap();
        let hash2 = BootloaderMonitorModule::compute_hash(&path).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_snapshot_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grub.cfg");
        fs::write(&path, "menuentry 'Ubuntu' {}").unwrap();

        let snap = BootloaderMonitorModule::snapshot_file(&path);
        assert!(snap.is_some());
        let snap = snap.unwrap();
        assert_eq!(snap.hash.len(), 64);
    }

    #[test]
    fn test_snapshot_file_nonexistent() {
        let snap = BootloaderMonitorModule::snapshot_file(Path::new("/nonexistent-grub"));
        assert!(snap.is_none());
    }

    #[test]
    fn test_extract_cmdline_params_normal() {
        let content = r#"
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX="console=tty0"
"#;
        let params = BootloaderMonitorModule::extract_cmdline_params(content);
        assert_eq!(params, vec!["quiet", "splash", "console=tty0"]);
    }

    #[test]
    fn test_extract_cmdline_params_empty() {
        let content = r#"
GRUB_DEFAULT=0
GRUB_CMDLINE_LINUX=""
"#;
        let params = BootloaderMonitorModule::extract_cmdline_params(content);
        assert!(params.is_empty());
    }

    #[test]
    fn test_extract_cmdline_params_with_comments() {
        let content = r#"
# GRUB_CMDLINE_LINUX="should_not_appear"
GRUB_CMDLINE_LINUX="real_param"
"#;
        let params = BootloaderMonitorModule::extract_cmdline_params(content);
        assert_eq!(params, vec!["real_param"]);
    }

    #[test]
    fn test_extract_cmdline_params_single_quotes() {
        let content = "GRUB_CMDLINE_LINUX='quiet splash'\n";
        let params = BootloaderMonitorModule::extract_cmdline_params(content);
        assert_eq!(params, vec!["quiet", "splash"]);
    }

    #[test]
    fn test_check_suspicious_params_init_change() {
        let params = vec!["init=/tmp/evil".to_string()];
        let suspicious = BootloaderMonitorModule::check_suspicious_params(&params);
        assert_eq!(suspicious.len(), 1);
        assert!(matches!(suspicious[0], SuspiciousParam::Critical(_)));
    }

    #[test]
    fn test_check_suspicious_params_init_normal() {
        let params = vec!["init=/sbin/init".to_string()];
        let suspicious = BootloaderMonitorModule::check_suspicious_params(&params);
        assert!(suspicious.is_empty());
    }

    #[test]
    fn test_check_suspicious_params_init_systemd() {
        let params = vec!["init=/lib/systemd/systemd".to_string()];
        let suspicious = BootloaderMonitorModule::check_suspicious_params(&params);
        assert!(suspicious.is_empty());
    }

    #[test]
    fn test_check_suspicious_params_selinux_disabled() {
        let params = vec!["selinux=0".to_string()];
        let suspicious = BootloaderMonitorModule::check_suspicious_params(&params);
        assert_eq!(suspicious.len(), 1);
        assert!(matches!(suspicious[0], SuspiciousParam::Critical(_)));
    }

    #[test]
    fn test_check_suspicious_params_apparmor_disabled() {
        let params = vec!["apparmor=0".to_string()];
        let suspicious = BootloaderMonitorModule::check_suspicious_params(&params);
        assert_eq!(suspicious.len(), 1);
        assert!(matches!(suspicious[0], SuspiciousParam::Critical(_)));
    }

    #[test]
    fn test_check_suspicious_params_module_sig_enforce() {
        let params = vec!["module.sig_enforce=0".to_string()];
        let suspicious = BootloaderMonitorModule::check_suspicious_params(&params);
        assert_eq!(suspicious.len(), 1);
        assert!(matches!(suspicious[0], SuspiciousParam::Critical(_)));
    }

    #[test]
    fn test_check_suspicious_params_nokaslr() {
        let params = vec!["nokaslr".to_string()];
        let suspicious = BootloaderMonitorModule::check_suspicious_params(&params);
        assert_eq!(suspicious.len(), 1);
        assert!(matches!(suspicious[0], SuspiciousParam::Elevated(_)));
    }

    #[test]
    fn test_check_suspicious_params_nosmep_nosmap() {
        let params = vec!["nosmep".to_string(), "nosmap".to_string()];
        let suspicious = BootloaderMonitorModule::check_suspicious_params(&params);
        assert_eq!(suspicious.len(), 2);
        assert!(matches!(suspicious[0], SuspiciousParam::Elevated(_)));
        assert!(matches!(suspicious[1], SuspiciousParam::Elevated(_)));
    }

    #[test]
    fn test_check_suspicious_params_noapic() {
        let params = vec!["noapic".to_string()];
        let suspicious = BootloaderMonitorModule::check_suspicious_params(&params);
        assert_eq!(suspicious.len(), 1);
        assert!(matches!(suspicious[0], SuspiciousParam::Warning(_)));
    }

    #[test]
    fn test_check_suspicious_params_nosmp() {
        let params = vec!["nosmp".to_string()];
        let suspicious = BootloaderMonitorModule::check_suspicious_params(&params);
        assert_eq!(suspicious.len(), 1);
        assert!(matches!(suspicious[0], SuspiciousParam::Warning(_)));
    }

    #[test]
    fn test_check_suspicious_params_normal() {
        let params = vec![
            "quiet".to_string(),
            "splash".to_string(),
            "console=tty0".to_string(),
        ];
        let suspicious = BootloaderMonitorModule::check_suspicious_params(&params);
        assert!(suspicious.is_empty());
    }

    #[test]
    fn test_check_suspicious_params_multiple() {
        let params = vec![
            "selinux=0".to_string(),
            "nokaslr".to_string(),
            "init=/tmp/evil".to_string(),
        ];
        let suspicious = BootloaderMonitorModule::check_suspicious_params(&params);
        assert_eq!(suspicious.len(), 3);
    }

    #[test]
    fn test_detect_changes_no_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grub.cfg");
        fs::write(&path, "content").unwrap();

        let snap1 = BootloaderMonitorModule::take_snapshot(&[path.clone()], &[]);
        let snap2 = BootloaderMonitorModule::take_snapshot(&[path], &[]);

        assert!(!BootloaderMonitorModule::detect_changes(
            &snap1,
            &snap2,
            true,
            &[],
            &[],
            &None
        ));
    }

    #[test]
    fn test_detect_changes_file_modified() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grub.cfg");
        fs::write(&path, "original content").unwrap();

        let old = BootloaderMonitorModule::take_snapshot(&[path.clone()], &[]);

        fs::write(&path, "modified content").unwrap();
        let new = BootloaderMonitorModule::take_snapshot(&[path.clone()], &[]);

        assert!(BootloaderMonitorModule::detect_changes(
            &old,
            &new,
            false,
            &[path],
            &[],
            &None
        ));
    }

    #[test]
    fn test_detect_changes_file_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grub.cfg");
        fs::write(&path, "content").unwrap();

        let old = BootloaderMonitorModule::take_snapshot(&[path.clone()], &[]);

        fs::remove_file(&path).unwrap();
        let new = BootloaderMonitorModule::take_snapshot(&[path.clone()], &[]);

        assert!(BootloaderMonitorModule::detect_changes(
            &old,
            &new,
            false,
            &[path],
            &[],
            &None
        ));
    }

    #[test]
    fn test_detect_changes_file_added() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grub.cfg");

        let old = BootloaderMonitorModule::take_snapshot(&[path.clone()], &[]);

        fs::write(&path, "new content").unwrap();
        let new = BootloaderMonitorModule::take_snapshot(&[path.clone()], &[]);

        assert!(BootloaderMonitorModule::detect_changes(
            &old,
            &new,
            false,
            &[path],
            &[],
            &None
        ));
    }

    #[test]
    fn test_detect_changes_permission_changed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grub.cfg");
        fs::write(&path, "content").unwrap();

        let old = BootloaderMonitorModule::take_snapshot(&[path.clone()], &[]);

        // パーミッションを変更
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        let new = BootloaderMonitorModule::take_snapshot(&[path.clone()], &[]);

        assert!(BootloaderMonitorModule::detect_changes(
            &old,
            &new,
            false,
            &[path],
            &[],
            &None
        ));
    }

    #[test]
    fn test_detect_changes_cmdline_suspicious() {
        let dir = tempfile::tempdir().unwrap();
        let default_grub = dir.path().join("default").join("grub");
        fs::create_dir_all(default_grub.parent().unwrap()).unwrap();
        fs::write(&default_grub, "GRUB_CMDLINE_LINUX=\"quiet\"\n").unwrap();

        let old = BootloaderMonitorModule::take_snapshot(&[default_grub.clone()], &[]);

        fs::write(&default_grub, "GRUB_CMDLINE_LINUX=\"quiet selinux=0\"\n").unwrap();
        let new = BootloaderMonitorModule::take_snapshot(&[default_grub.clone()], &[]);

        assert!(BootloaderMonitorModule::detect_changes(
            &old,
            &new,
            true,
            &[default_grub],
            &[],
            &None
        ));
    }

    #[test]
    fn test_find_efi_grub_configs() {
        let dir = tempfile::tempdir().unwrap();
        let efi_dir = dir.path().join("EFI");
        let ubuntu_dir = efi_dir.join("ubuntu");
        fs::create_dir_all(&ubuntu_dir).unwrap();
        fs::write(ubuntu_dir.join("grub.cfg"), "content").unwrap();
        fs::write(ubuntu_dir.join("other.cfg"), "other").unwrap();

        let results = BootloaderMonitorModule::find_efi_grub_configs(&[efi_dir]);
        assert_eq!(results.len(), 1);
        assert!(results[0].ends_with("grub.cfg"));
    }

    #[test]
    fn test_find_efi_grub_configs_empty() {
        let results =
            BootloaderMonitorModule::find_efi_grub_configs(&[PathBuf::from("/nonexistent-efi")]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_collect_target_paths_dedup() {
        let paths = vec![
            PathBuf::from("/boot/grub/grub.cfg"),
            PathBuf::from("/boot/grub/grub.cfg"),
        ];
        let result = BootloaderMonitorModule::collect_target_paths(&paths, &[]);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_init_zero_interval() {
        let config = BootloaderMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            grub_paths: vec![],
            efi_grub_dirs: vec![],
            alert_on_cmdline_changes: true,
        };
        let mut module = BootloaderMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = BootloaderMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
            grub_paths: vec![PathBuf::from("/nonexistent-grub-path")],
            efi_grub_dirs: vec![],
            alert_on_cmdline_changes: true,
        };
        let mut module = BootloaderMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grub.cfg");
        fs::write(&path, "menuentry 'Test' {}").unwrap();

        let config = BootloaderMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            grub_paths: vec![path],
            efi_grub_dirs: vec![],
            alert_on_cmdline_changes: true,
        };
        let mut module = BootloaderMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_start_with_no_files() {
        let config = BootloaderMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            grub_paths: vec![PathBuf::from("/nonexistent-grub-path")],
            efi_grub_dirs: vec![],
            alert_on_cmdline_changes: false,
        };
        let mut module = BootloaderMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan_with_files() {
        let dir = tempfile::tempdir().unwrap();
        let grub_cfg = dir.path().join("grub.cfg");
        let default_grub = dir.path().join("default").join("grub");
        fs::create_dir_all(default_grub.parent().unwrap()).unwrap();
        fs::write(&grub_cfg, "menuentry 'Test' {}").unwrap();
        fs::write(&default_grub, "GRUB_CMDLINE_LINUX=\"quiet splash\"\n").unwrap();

        let config = test_config(dir.path());
        let config = BootloaderMonitorConfig {
            grub_paths: vec![grub_cfg, default_grub],
            ..config
        };
        let module = BootloaderMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("2件"));
    }

    #[tokio::test]
    async fn test_initial_scan_detects_suspicious_cmdline() {
        let dir = tempfile::tempdir().unwrap();
        let default_grub = dir.path().join("default").join("grub");
        fs::create_dir_all(default_grub.parent().unwrap()).unwrap();
        fs::write(
            &default_grub,
            "GRUB_CMDLINE_LINUX=\"quiet selinux=0 nokaslr\"\n",
        )
        .unwrap();

        let config = BootloaderMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
            grub_paths: vec![default_grub],
            efi_grub_dirs: vec![],
            alert_on_cmdline_changes: true,
        };
        let module = BootloaderMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 2); // selinux=0 + nokaslr
    }

    #[tokio::test]
    async fn test_initial_scan_nonexistent_files() {
        let config = BootloaderMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
            grub_paths: vec![PathBuf::from("/nonexistent-grub-scan")],
            efi_grub_dirs: vec![],
            alert_on_cmdline_changes: true,
        };
        let module = BootloaderMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[tokio::test]
    async fn test_initial_scan_efi_files() {
        let dir = tempfile::tempdir().unwrap();
        let efi_dir = dir.path().join("EFI");
        let ubuntu_dir = efi_dir.join("ubuntu");
        fs::create_dir_all(&ubuntu_dir).unwrap();
        fs::write(ubuntu_dir.join("grub.cfg"), "menuentry 'Ubuntu' {}").unwrap();

        let config = BootloaderMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
            grub_paths: vec![],
            efi_grub_dirs: vec![efi_dir],
            alert_on_cmdline_changes: false,
        };
        let module = BootloaderMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
    }

    #[test]
    fn test_module_name() {
        let config = BootloaderMonitorConfig::default();
        let module = BootloaderMonitorModule::new(config, None);
        assert_eq!(module.name(), "bootloader_monitor");
    }
}
