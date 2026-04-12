//! ハニーポットファイル（カナリアトークン）監視モジュール
//!
//! 指定したデコイファイル・ディレクトリへのアクセスを inotify でリアルタイム監視し、
//! 不正アクセスの兆候を検知する。正常運用では誰もアクセスしないファイルを設置し、
//! アクセスが発生した時点で侵入の早期警告とする。
//!
//! 検知対象:
//! - ファイル読み取り / オープン（ACCESS, OPEN）— Warning
//! - ファイル変更（MODIFY）— Critical
//! - ファイル削除（DELETE, DELETE_SELF）— Critical
//! - ファイル移動（MOVED_TO, MOVED_FROM）— Critical
//! - 属性変更（ATTRIB）— Warning
//! - ヘルスチェックによるファイル消失検知 — Critical

use crate::config::HoneypotMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// ハニーポットファイル（カナリアトークン）監視モジュール
///
/// 指定したデコイファイル・ディレクトリへのアクセスを inotify でリアルタイム監視し、
/// 不正アクセスの兆候を検知する。
pub struct HoneypotMonitorModule {
    config: HoneypotMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl HoneypotMonitorModule {
    /// 新しいハニーポット監視モジュールを作成する
    pub fn new(config: HoneypotMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// EventMask からイベントタイプ文字列を返す
    fn event_type_for_mask(mask: EventMask) -> Option<&'static str> {
        if mask.contains(EventMask::ACCESS) {
            Some("honeypot_accessed")
        } else if mask.contains(EventMask::OPEN) {
            Some("honeypot_opened")
        } else if mask.contains(EventMask::MODIFY) {
            Some("honeypot_modified")
        } else if mask.contains(EventMask::DELETE) || mask.contains(EventMask::DELETE_SELF) {
            Some("honeypot_deleted")
        } else if mask.contains(EventMask::MOVED_TO) || mask.contains(EventMask::MOVED_FROM) {
            Some("honeypot_moved")
        } else if mask.contains(EventMask::ATTRIB) {
            Some("honeypot_attrib_changed")
        } else {
            None
        }
    }

    /// EventMask から Severity を決定する
    fn severity_for_event(mask: EventMask) -> Severity {
        if mask.contains(EventMask::MODIFY)
            || mask.contains(EventMask::DELETE)
            || mask.contains(EventMask::DELETE_SELF)
            || mask.contains(EventMask::MOVED_TO)
            || mask.contains(EventMask::MOVED_FROM)
        {
            Severity::Critical
        } else {
            // ACCESS, OPEN, ATTRIB
            Severity::Warning
        }
    }

    /// EventMask から人間向けメッセージを返す
    fn message_for_event(event_type: &str) -> &'static str {
        match event_type {
            "honeypot_accessed" => "ハニーポットファイルが読み取られました",
            "honeypot_opened" => "ハニーポットファイルがオープンされました",
            "honeypot_modified" => "ハニーポットファイルが変更されました",
            "honeypot_deleted" => "ハニーポットファイルが削除されました",
            "honeypot_moved" => "ハニーポットファイルが移動されました",
            "honeypot_attrib_changed" => "ハニーポットファイルの属性が変更されました",
            _ => "ハニーポットファイルへのアクセスを検知しました",
        }
    }

    /// 再帰的にディレ���トリを列挙し、inotify watch を登録する
    fn register_watches(
        inotify: &mut Inotify,
        path: &Path,
        recursive: bool,
        watch_map: &mut HashMap<WatchDescriptor, PathBuf>,
        watch_mask: WatchMask,
    ) -> Result<(), AppError> {
        if !path.exists() {
            tracing::warn!(
                path = %path.display(),
                "ハニーポットファイルが存在しません。監視をスキップします"
            );
            return Ok(());
        }

        if path.is_file() {
            if let Some(parent) = path.parent()
                && !watch_map.values().any(|p| p == parent)
            {
                match inotify.watches().add(parent, watch_mask) {
                    Ok(wd) => {
                        watch_map.insert(wd, parent.to_path_buf());
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            path = %parent.display(),
                            "inotify watch の登録に失敗しました"
                        );
                    }
                }
            }
            return Ok(());
        }

        if path.is_dir() {
            match inotify.watches().add(path, watch_mask) {
                Ok(wd) => {
                    watch_map.insert(wd, path.to_path_buf());
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "inotify watch の登録に失敗しました"
                    );
                    return Ok(());
                }
            }

            if recursive {
                let entries = match std::fs::read_dir(path) {
                    Ok(entries) => entries,
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            path = %path.display(),
                            "ディレクトリの読み取りに失敗しました"
                        );
                        return Ok(());
                    }
                };

                for entry in entries.filter_map(|e| e.ok()) {
                    let entry_path = entry.path();
                    let metadata = match entry.metadata() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };

                    if metadata.is_dir() && !metadata.file_type().is_symlink() {
                        Self::register_watches(
                            inotify,
                            &entry_path,
                            recursive,
                            watch_map,
                            watch_mask,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    /// ハニーポットパスのメタデータスナップショットを作成する
    fn scan_paths(watch_paths: &[PathBuf]) -> BTreeMap<String, String> {
        let mut snapshot = BTreeMap::new();

        for path in watch_paths {
            if !path.exists() {
                snapshot.insert(path.display().to_string(), "missing".to_string());
                continue;
            }

            let metadata_str = match std::fs::metadata(path) {
                Ok(m) => format!("size={}, readonly={}", m.len(), m.permissions().readonly()),
                Err(_) => "error".to_string(),
            };
            snapshot.insert(path.display().to_string(), metadata_str);

            if path.is_dir() {
                Self::scan_dir_recursive(path, &mut snapshot);
            }
        }

        snapshot
    }

    /// ディレクトリを再帰的にスキャンしてスナップショットに追加する
    fn scan_dir_recursive(path: &Path, snapshot: &mut BTreeMap<String, String>) {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let entry_path = entry.path();
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            let metadata_str = format!(
                "size={}, readonly={}",
                metadata.len(),
                metadata.permissions().readonly()
            );
            snapshot.insert(entry_path.display().to_string(), metadata_str);

            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Self::scan_dir_recursive(&entry_path, snapshot);
            }
        }
    }

    /// ファイルパスがハニーポット監視対象かどうかを判定する
    fn is_honeypot_path(file_path: &Path, watch_paths: &[PathBuf]) -> bool {
        watch_paths.iter().any(|hp| {
            if hp.is_file() {
                file_path == hp
            } else {
                file_path.starts_with(hp)
            }
        })
    }
}

impl Module for HoneypotMonitorModule {
    fn name(&self) -> &str {
        "honeypot_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.watch_paths.is_empty() {
            return Err(AppError::ModuleConfig {
                message: "watch_paths を 1 つ以上指定してください".to_string(),
            });
        }

        let mut existing = 0;
        let mut missing = 0;
        for path in &self.config.watch_paths {
            if path.exists() {
                existing += 1;
            } else {
                missing += 1;
                tracing::warn!(
                    path = %path.display(),
                    "ハニーポットファイルが存在しません"
                );
            }
        }

        tracing::info!(
            watch_paths = self.config.watch_paths.len(),
            existing = existing,
            missing = missing,
            recursive = self.config.recursive,
            debounce_ms = self.config.debounce_ms,
            health_check_interval_secs = self.config.health_check_interval_secs,
            "ハニーポット監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let mut inotify = Inotify::init().map_err(|e| AppError::ModuleConfig {
            message: format!("inotify ���初期化に失敗しました: {}", e),
        })?;

        let watch_mask = WatchMask::ACCESS
            | WatchMask::OPEN
            | WatchMask::MODIFY
            | WatchMask::DELETE
            | WatchMask::DELETE_SELF
            | WatchMask::MOVED_TO
            | WatchMask::MOVED_FROM
            | WatchMask::ATTRIB;

        let mut watch_map: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

        for watch_path in &self.config.watch_paths {
            Self::register_watches(
                &mut inotify,
                watch_path,
                self.config.recursive,
                &mut watch_map,
                watch_mask,
            )?;
        }

        tracing::info!(
            watch_count = watch_map.len(),
            "ハニーポット inotify watch を登録しました"
        );

        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let debounce_ms = self.config.debounce_ms;
        let health_check_secs = self.config.health_check_interval_secs;
        let watch_paths = self.config.watch_paths.clone();

        let handle = tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            let mut debounce_map: HashMap<PathBuf, Instant> = HashMap::new();
            let debounce_duration = Duration::from_millis(debounce_ms);
            let mut poll_interval = tokio::time::interval(Duration::from_millis(100));
            poll_interval.tick().await;
            let mut health_interval = tokio::time::interval(Duration::from_secs(health_check_secs));
            health_interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ハニーポット監視モジュールを停止します");
                        break;
                    }
                    _ = health_interval.tick() => {
                        for path in &watch_paths {
                            if !path.exists() {
                                tracing::warn!(
                                    path = %path.display(),
                                    "ハニーポットファイルが消失しています"
                                );
                                if let Some(bus) = &event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "honeypot_missing",
                                            Severity::Critical,
                                            "honeypot_monitor",
                                            "ハニーポットファイルが消失���ています（証拠隠滅の可能性）",
                                        )
                                        .with_details(format!("path={}", path.display())),
                                    );
                                }
                            }
                        }
                    }
                    _ = poll_interval.tick() => {
                        let events = match inotify.read_events(&mut buffer) {
                            Ok(events) => events,
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                            Err(e) => {
                                tracing::error!(error = %e, "inotify イベントの読み取りに失敗しました");
                                continue;
                            }
                        };

                        let now = Instant::now();

                        for event in events {
                            let dir_path = match watch_map.get(&event.wd) {
                                Some(p) => p.clone(),
                                None => continue,
                            };

                            let file_path = match &event.name {
                                Some(name) => dir_path.join(name),
                                None => dir_path.clone(),
                            };

                            if !Self::is_honeypot_path(&file_path, &watch_paths) {
                                continue;
                            }

                            // デバウンス
                            if let Some(last_time) = debounce_map.get(&file_path)
                                && now.duration_since(*last_time) < debounce_duration
                            {
                                continue;
                            }
                            debounce_map.insert(file_path.clone(), now);

                            let event_type = match Self::event_type_for_mask(event.mask) {
                                Some(et) => et,
                                None => continue,
                            };

                            let severity = Self::severity_for_event(event.mask);
                            let message = Self::message_for_event(event_type);

                            tracing::warn!(
                                path = %file_path.display(),
                                event_type = event_type,
                                severity = %severity,
                                "{}", message
                            );

                            if let Some(bus) = &event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        event_type,
                                        severity,
                                        "honeypot_monitor",
                                        message,
                                    )
                                    .with_details(format!("path={}", file_path.display())),
                                );
                            }
                        }

                        if debounce_map.len() > 10000 {
                            let threshold = now - Duration::from_secs(60);
                            debounce_map.retain(|_, t| *t > threshold);
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = Instant::now();

        let snapshot = Self::scan_paths(&self.config.watch_paths);

        let items_scanned = snapshot.len();
        let issues_found = snapshot.values().filter(|v| *v == "missing").count();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "{}件のハニーポットパスをスキャンしました（{}件が見つかりません）",
                items_scanned, issues_found
            ),
            snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_config(dir: &Path) -> HoneypotMonitorConfig {
        HoneypotMonitorConfig {
            enabled: true,
            watch_paths: vec![dir.to_path_buf()],
            recursive: false,
            debounce_ms: 500,
            health_check_interval_secs: 300,
        }
    }

    #[test]
    fn test_event_type_for_mask() {
        assert_eq!(
            HoneypotMonitorModule::event_type_for_mask(EventMask::ACCESS),
            Some("honeypot_accessed")
        );
        assert_eq!(
            HoneypotMonitorModule::event_type_for_mask(EventMask::OPEN),
            Some("honeypot_opened")
        );
        assert_eq!(
            HoneypotMonitorModule::event_type_for_mask(EventMask::MODIFY),
            Some("honeypot_modified")
        );
        assert_eq!(
            HoneypotMonitorModule::event_type_for_mask(EventMask::DELETE),
            Some("honeypot_deleted")
        );
        assert_eq!(
            HoneypotMonitorModule::event_type_for_mask(EventMask::DELETE_SELF),
            Some("honeypot_deleted")
        );
        assert_eq!(
            HoneypotMonitorModule::event_type_for_mask(EventMask::MOVED_TO),
            Some("honeypot_moved")
        );
        assert_eq!(
            HoneypotMonitorModule::event_type_for_mask(EventMask::MOVED_FROM),
            Some("honeypot_moved")
        );
        assert_eq!(
            HoneypotMonitorModule::event_type_for_mask(EventMask::ATTRIB),
            Some("honeypot_attrib_changed")
        );
        assert_eq!(
            HoneypotMonitorModule::event_type_for_mask(EventMask::IGNORED),
            None
        );
    }

    #[test]
    fn test_severity_for_event() {
        assert_eq!(
            HoneypotMonitorModule::severity_for_event(EventMask::ACCESS),
            Severity::Warning
        );
        assert_eq!(
            HoneypotMonitorModule::severity_for_event(EventMask::OPEN),
            Severity::Warning
        );
        assert_eq!(
            HoneypotMonitorModule::severity_for_event(EventMask::ATTRIB),
            Severity::Warning
        );
        assert_eq!(
            HoneypotMonitorModule::severity_for_event(EventMask::MODIFY),
            Severity::Critical
        );
        assert_eq!(
            HoneypotMonitorModule::severity_for_event(EventMask::DELETE),
            Severity::Critical
        );
        assert_eq!(
            HoneypotMonitorModule::severity_for_event(EventMask::DELETE_SELF),
            Severity::Critical
        );
        assert_eq!(
            HoneypotMonitorModule::severity_for_event(EventMask::MOVED_TO),
            Severity::Critical
        );
        assert_eq!(
            HoneypotMonitorModule::severity_for_event(EventMask::MOVED_FROM),
            Severity::Critical
        );
    }

    #[test]
    fn test_message_for_event() {
        assert_eq!(
            HoneypotMonitorModule::message_for_event("honeypot_accessed"),
            "ハニーポットファイルが読み取られました"
        );
        assert_eq!(
            HoneypotMonitorModule::message_for_event("honeypot_modified"),
            "ハニーポットファイルが変更されました"
        );
        assert_eq!(
            HoneypotMonitorModule::message_for_event("honeypot_deleted"),
            "ハニーポットファイルが削除されました"
        );
        assert_eq!(
            HoneypotMonitorModule::message_for_event("unknown"),
            "ハニーポットファイルへのアクセスを検知しました"
        );
    }

    #[test]
    fn test_init_empty_watch_paths() {
        let config = HoneypotMonitorConfig {
            enabled: true,
            watch_paths: vec![],
            recursive: false,
            debounce_ms: 500,
            health_check_interval_secs: 300,
        };
        let mut module = HoneypotMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_with_valid_paths() {
        let dir = TempDir::new().unwrap();
        let config = make_config(dir.path());
        let mut module = HoneypotMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_with_nonexistent_path() {
        let config = HoneypotMonitorConfig {
            enabled: true,
            watch_paths: vec![PathBuf::from("/nonexistent/honeypot/file")],
            recursive: false,
            debounce_ms: 500,
            health_check_interval_secs: 300,
        };
        let mut module = HoneypotMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_scan_paths_with_existing_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("honeypot.txt");
        fs::write(&file_path, "canary token").unwrap();

        let snapshot = HoneypotMonitorModule::scan_paths(&[file_path.clone()]);
        assert!(snapshot.contains_key(&file_path.display().to_string()));
        let value = &snapshot[&file_path.display().to_string()];
        assert!(value.starts_with("size="));
    }

    #[test]
    fn test_scan_paths_with_missing_file() {
        let snapshot =
            HoneypotMonitorModule::scan_paths(&[PathBuf::from("/nonexistent/honeypot.txt")]);
        assert_eq!(
            snapshot.get("/nonexistent/honeypot.txt"),
            Some(&"missing".to_string())
        );
    }

    #[test]
    fn test_scan_paths_with_directory() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("secret.txt");
        fs::write(&file_path, "secret data").unwrap();

        let snapshot = HoneypotMonitorModule::scan_paths(&[dir.path().to_path_buf()]);
        assert!(snapshot.len() >= 2);
        assert!(snapshot.contains_key(&dir.path().display().to_string()));
        assert!(snapshot.contains_key(&file_path.display().to_string()));
    }

    #[test]
    fn test_is_honeypot_path() {
        let dir = PathBuf::from("/var/honeypot");
        let file = PathBuf::from("/etc/shadow.bak");
        let watch_paths = vec![dir.clone(), file.clone()];

        assert!(HoneypotMonitorModule::is_honeypot_path(
            &PathBuf::from("/var/honeypot/secret.txt"),
            &watch_paths
        ));
        assert!(HoneypotMonitorModule::is_honeypot_path(
            &PathBuf::from("/etc/shadow.bak"),
            &watch_paths
        ));
        assert!(!HoneypotMonitorModule::is_honeypot_path(
            &PathBuf::from("/etc/passwd"),
            &watch_paths
        ));
    }

    #[test]
    fn test_name() {
        let config = HoneypotMonitorConfig::default();
        let module = HoneypotMonitorModule::new(config, None);
        assert_eq!(module.name(), "honeypot_monitor");
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("honeypot.txt");
        fs::write(&file_path, "canary").unwrap();

        let config = make_config(dir.path());
        let module = HoneypotMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert!(result.items_scanned >= 2);
        assert_eq!(result.issues_found, 0);
    }

    #[tokio::test]
    async fn test_initial_scan_with_missing_paths() {
        let config = HoneypotMonitorConfig {
            enabled: true,
            watch_paths: vec![PathBuf::from("/nonexistent/path")],
            recursive: false,
            debounce_ms: 500,
            health_check_interval_secs: 300,
        };
        let module = HoneypotMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 1);
    }

    #[tokio::test]
    async fn test_stop() {
        let config = HoneypotMonitorConfig::default();
        let mut module = HoneypotMonitorModule::new(config, None);
        assert!(module.stop().await.is_ok());
    }
}
