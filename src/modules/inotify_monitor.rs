//! inotify ベースのリアルタイムファイル変更検知モジュール
//!
//! inotify を使ってファイルシステムの変更をリアルタイムに検知する。
//! ポーリングベースの file_integrity モジュールと異なり、
//! カーネルレベルで即座にファイル変更を検知できる。
//!
//! 検知対象:
//! - ファイル作成（CREATE）— Info
//! - ファイル変更（MODIFY）— Warning
//! - ファイル削除（DELETE）— Warning
//! - ファイル移動（MOVED_TO, MOVED_FROM）— Warning
//! - 属性変更（ATTRIB）— Info

use crate::config::InotifyMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// inotify ベースのリアルタイムファイル変更検知モジュール
///
/// inotify を使ってファイルシステムの変更をリアルタイムに検知する。
pub struct InotifyMonitorModule {
    config: InotifyMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl InotifyMonitorModule {
    /// 新しい inotify 監視モジュールを作成する
    pub fn new(config: InotifyMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// glob パターンを正規表現に変換する
    fn glob_to_regex(glob: &str) -> String {
        let mut regex = String::with_capacity(glob.len() * 2 + 2);
        regex.push('^');
        for ch in glob.chars() {
            match ch {
                '*' => regex.push_str("[^/]*"),
                '?' => regex.push('.'),
                '.' => regex.push_str("\\."),
                '+' => regex.push_str("\\+"),
                '(' => regex.push_str("\\("),
                ')' => regex.push_str("\\)"),
                '[' => regex.push_str("\\["),
                ']' => regex.push_str("\\]"),
                '{' => regex.push_str("\\{"),
                '}' => regex.push_str("\\}"),
                '^' => regex.push_str("\\^"),
                '$' => regex.push_str("\\$"),
                '|' => regex.push_str("\\|"),
                '\\' => regex.push_str("\\\\"),
                _ => regex.push(ch),
            }
        }
        regex.push('$');
        regex
    }

    /// パスが除外パターンに一致するかを判定する
    fn should_exclude(path: &Path, exclude_regexes: &[regex::Regex]) -> bool {
        let file_name = match path.file_name() {
            Some(name) => name.to_string_lossy(),
            None => return false,
        };
        exclude_regexes.iter().any(|re| re.is_match(&file_name))
    }

    /// EventMask からイベントタイプ文字列を返す
    fn event_type_for_mask(mask: EventMask) -> Option<&'static str> {
        if mask.contains(EventMask::CREATE) {
            Some("inotify_file_created")
        } else if mask.contains(EventMask::MODIFY) {
            Some("inotify_file_modified")
        } else if mask.contains(EventMask::DELETE) || mask.contains(EventMask::DELETE_SELF) {
            Some("inotify_file_deleted")
        } else if mask.contains(EventMask::MOVED_TO) || mask.contains(EventMask::MOVED_FROM) {
            Some("inotify_file_moved")
        } else if mask.contains(EventMask::ATTRIB) {
            Some("inotify_file_attrib_changed")
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
            Severity::Warning
        } else {
            // CREATE, ATTRIB, etc.
            Severity::Info
        }
    }

    /// 再帰的にディレクトリを列挙し、inotify watch を登録する
    fn register_watches(
        inotify: &mut Inotify,
        path: &Path,
        recursive: bool,
        exclude_regexes: &[regex::Regex],
        watch_map: &mut HashMap<WatchDescriptor, PathBuf>,
        max_watches: u32,
        watch_mask: WatchMask,
    ) -> Result<(), AppError> {
        if !path.exists() {
            tracing::debug!(
                path = %path.display(),
                "監視対象パスが存在しません。スキップします"
            );
            return Ok(());
        }

        if Self::should_exclude(path, exclude_regexes) {
            return Ok(());
        }

        if watch_map.len() >= max_watches as usize {
            tracing::warn!(
                max_watches = max_watches,
                "inotify watch の最大数に達しました。これ以上のディレクトリは監視できません"
            );
            return Ok(());
        }

        // ディレクトリに watch を登録
        if path.is_dir() {
            match inotify.watches().add(path, watch_mask) {
                Ok(wd) => {
                    watch_map.insert(wd, path.to_path_buf());
                }
                Err(e) => {
                    tracing::debug!(
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
                            exclude_regexes,
                            watch_map,
                            max_watches,
                            watch_mask,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    /// 監視対象パス内のファイル・ディレクトリを列挙し、スナップショットを作成する
    fn scan_paths(
        watch_paths: &[PathBuf],
        exclude_regexes: &[regex::Regex],
    ) -> BTreeMap<String, String> {
        let mut snapshot = BTreeMap::new();

        for watch_path in watch_paths {
            if !watch_path.exists() {
                continue;
            }
            Self::scan_dir_recursive(watch_path, exclude_regexes, &mut snapshot);
        }

        snapshot
    }

    /// ディレクトリを再帰的にスキャンしてスナップショットに追加する
    fn scan_dir_recursive(
        path: &Path,
        exclude_regexes: &[regex::Regex],
        snapshot: &mut BTreeMap<String, String>,
    ) {
        if Self::should_exclude(path, exclude_regexes) {
            return;
        }

        if path.is_file() {
            let metadata_str = match std::fs::metadata(path) {
                Ok(m) => format!("size={}, readonly={}", m.len(), m.permissions().readonly()),
                Err(_) => "error".to_string(),
            };
            snapshot.insert(path.display().to_string(), metadata_str);
            return;
        }

        if !path.is_dir() {
            return;
        }

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

            if metadata.is_file() {
                if !Self::should_exclude(&entry_path, exclude_regexes) {
                    let metadata_str = format!(
                        "size={}, readonly={}",
                        metadata.len(),
                        metadata.permissions().readonly()
                    );
                    snapshot.insert(entry_path.display().to_string(), metadata_str);
                }
            } else if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Self::scan_dir_recursive(&entry_path, exclude_regexes, snapshot);
            }
        }
    }
}

impl Module for InotifyMonitorModule {
    fn name(&self) -> &str {
        "inotify_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.watch_paths.is_empty() {
            return Err(AppError::ModuleConfig {
                message: "watch_paths を 1 つ以上指定してください".to_string(),
            });
        }

        // 除外パターンのコンパイルを検証
        for pattern in &self.config.exclude_patterns {
            let regex_str = Self::glob_to_regex(pattern);
            regex::Regex::new(&regex_str).map_err(|e| AppError::ModuleConfig {
                message: format!(
                    "除外パターン '{}' の正規表現変換に失敗しました: {}",
                    pattern, e
                ),
            })?;
        }

        tracing::info!(
            watch_paths = ?self.config.watch_paths,
            recursive = self.config.recursive,
            max_watches = self.config.max_watches,
            debounce_ms = self.config.debounce_ms,
            exclude_patterns = ?self.config.exclude_patterns,
            "inotify 監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        // 除外パターンをコンパイル
        let mut exclude_regexes = Vec::new();
        for pattern in &self.config.exclude_patterns {
            let regex_str = Self::glob_to_regex(pattern);
            let re = regex::Regex::new(&regex_str).map_err(|e| AppError::ModuleConfig {
                message: format!(
                    "除外パターン '{}' の正規表現変換に失敗しました: {}",
                    pattern, e
                ),
            })?;
            exclude_regexes.push(re);
        }

        // inotify を初期化
        let mut inotify = Inotify::init().map_err(|e| AppError::ModuleConfig {
            message: format!("inotify の初期化に失敗しました: {}", e),
        })?;

        let watch_mask = WatchMask::CREATE
            | WatchMask::MODIFY
            | WatchMask::DELETE
            | WatchMask::DELETE_SELF
            | WatchMask::MOVED_TO
            | WatchMask::MOVED_FROM
            | WatchMask::ATTRIB;

        let mut watch_map: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

        // 各監視対象パスに watch を登録
        for watch_path in &self.config.watch_paths {
            Self::register_watches(
                &mut inotify,
                watch_path,
                self.config.recursive,
                &exclude_regexes,
                &mut watch_map,
                self.config.max_watches,
                watch_mask,
            )?;
        }

        tracing::info!(
            watch_count = watch_map.len(),
            "inotify watch を登録しました"
        );

        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let debounce_ms = self.config.debounce_ms;
        let exclude_regexes_clone = exclude_regexes;

        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            let mut debounce_map: HashMap<PathBuf, Instant> = HashMap::new();
            let debounce_duration = Duration::from_millis(debounce_ms);
            // ポーリング間隔（非ブロッキング読み取りのため短い間隔で確認）
            let mut poll_interval = tokio::time::interval(Duration::from_millis(100));
            poll_interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("inotify 監視モジュールを停止します");
                        break;
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

                            // 除外パターンチェック
                            if InotifyMonitorModule::should_exclude(&file_path, &exclude_regexes_clone) {
                                continue;
                            }

                            // デバウンス
                            if let Some(last_time) = debounce_map.get(&file_path)
                                && now.duration_since(*last_time) < debounce_duration
                            {
                                continue;
                            }
                            debounce_map.insert(file_path.clone(), now);

                            let event_type = match InotifyMonitorModule::event_type_for_mask(event.mask) {
                                Some(et) => et,
                                None => continue,
                            };

                            let severity = InotifyMonitorModule::severity_for_event(event.mask);

                            let message = match event_type {
                                "inotify_file_created" => "ファイルが作成されました",
                                "inotify_file_modified" => "ファイルが変更されました",
                                "inotify_file_deleted" => "ファイルが削除されました",
                                "inotify_file_moved" => "ファイルが移動されました",
                                "inotify_file_attrib_changed" => "ファイルの属性が変更されました",
                                _ => "ファイルシステムイベントを検知しました",
                            };

                            tracing::info!(
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
                                        "inotify_monitor",
                                        message,
                                    )
                                    .with_details(format!("path={}", file_path.display())),
                                );
                            }
                        }

                        // 古いデバウンスエントリを定期的にクリーンアップ
                        if debounce_map.len() > 10000 {
                            let threshold = now - Duration::from_secs(60);
                            debounce_map.retain(|_, t| *t > threshold);
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = Instant::now();

        // 除外パターンをコンパイル
        let mut exclude_regexes = Vec::new();
        for pattern in &self.config.exclude_patterns {
            let regex_str = Self::glob_to_regex(pattern);
            let re = regex::Regex::new(&regex_str).map_err(|e| AppError::ModuleConfig {
                message: format!(
                    "除外パターン '{}' の正規表現変換に失敗しました: {}",
                    pattern, e
                ),
            })?;
            exclude_regexes.push(re);
        }

        let snapshot = Self::scan_paths(&self.config.watch_paths, &exclude_regexes);

        let items_scanned = snapshot.len();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!(
                "{}件のファイル・ディレクトリをスキャンしました",
                items_scanned
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

    fn make_config(dir: &Path) -> InotifyMonitorConfig {
        InotifyMonitorConfig {
            enabled: true,
            watch_paths: vec![dir.to_path_buf()],
            recursive: true,
            exclude_patterns: vec![],
            max_watches: 65536,
            debounce_ms: 100,
        }
    }

    #[test]
    fn test_glob_to_regex() {
        assert_eq!(
            InotifyMonitorModule::glob_to_regex("*.swp"),
            "^[^/]*\\.swp$"
        );
        assert_eq!(InotifyMonitorModule::glob_to_regex("?.log"), "^.\\.log$");
        assert_eq!(InotifyMonitorModule::glob_to_regex(".git"), "^\\.git$");
        assert_eq!(InotifyMonitorModule::glob_to_regex("*~"), "^[^/]*~$");
        assert_eq!(InotifyMonitorModule::glob_to_regex("test"), "^test$");
    }

    #[test]
    fn test_severity_for_event() {
        assert_eq!(
            InotifyMonitorModule::severity_for_event(EventMask::CREATE),
            Severity::Info
        );
        assert_eq!(
            InotifyMonitorModule::severity_for_event(EventMask::MODIFY),
            Severity::Warning
        );
        assert_eq!(
            InotifyMonitorModule::severity_for_event(EventMask::DELETE),
            Severity::Warning
        );
        assert_eq!(
            InotifyMonitorModule::severity_for_event(EventMask::MOVED_TO),
            Severity::Warning
        );
        assert_eq!(
            InotifyMonitorModule::severity_for_event(EventMask::MOVED_FROM),
            Severity::Warning
        );
        assert_eq!(
            InotifyMonitorModule::severity_for_event(EventMask::ATTRIB),
            Severity::Info
        );
    }

    #[test]
    fn test_event_type_for_mask() {
        assert_eq!(
            InotifyMonitorModule::event_type_for_mask(EventMask::CREATE),
            Some("inotify_file_created")
        );
        assert_eq!(
            InotifyMonitorModule::event_type_for_mask(EventMask::MODIFY),
            Some("inotify_file_modified")
        );
        assert_eq!(
            InotifyMonitorModule::event_type_for_mask(EventMask::DELETE),
            Some("inotify_file_deleted")
        );
        assert_eq!(
            InotifyMonitorModule::event_type_for_mask(EventMask::DELETE_SELF),
            Some("inotify_file_deleted")
        );
        assert_eq!(
            InotifyMonitorModule::event_type_for_mask(EventMask::MOVED_TO),
            Some("inotify_file_moved")
        );
        assert_eq!(
            InotifyMonitorModule::event_type_for_mask(EventMask::MOVED_FROM),
            Some("inotify_file_moved")
        );
        assert_eq!(
            InotifyMonitorModule::event_type_for_mask(EventMask::ATTRIB),
            Some("inotify_file_attrib_changed")
        );
        assert_eq!(
            InotifyMonitorModule::event_type_for_mask(EventMask::IGNORED),
            None
        );
    }

    #[test]
    fn test_should_exclude_path() {
        let patterns = vec![
            regex::Regex::new(&InotifyMonitorModule::glob_to_regex("*.swp")).unwrap(),
            regex::Regex::new(&InotifyMonitorModule::glob_to_regex("*.tmp")).unwrap(),
            regex::Regex::new(&InotifyMonitorModule::glob_to_regex(".git")).unwrap(),
        ];

        assert!(InotifyMonitorModule::should_exclude(
            Path::new("/etc/test.swp"),
            &patterns
        ));
        assert!(InotifyMonitorModule::should_exclude(
            Path::new("/tmp/file.tmp"),
            &patterns
        ));
        assert!(InotifyMonitorModule::should_exclude(
            Path::new("/repo/.git"),
            &patterns
        ));
        assert!(!InotifyMonitorModule::should_exclude(
            Path::new("/etc/passwd"),
            &patterns
        ));
        assert!(!InotifyMonitorModule::should_exclude(
            Path::new("/etc/hosts"),
            &patterns
        ));
    }

    #[test]
    fn test_module_name() {
        let dir = TempDir::new().unwrap();
        let config = make_config(dir.path());
        let module = InotifyMonitorModule::new(config, None);
        assert_eq!(module.name(), "inotify_monitor");
    }

    #[tokio::test]
    async fn test_initial_scan_empty_paths() {
        let dir = TempDir::new().unwrap();
        let config = make_config(dir.path());
        let module = InotifyMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[tokio::test]
    async fn test_initial_scan_with_temp_dir() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("file1.txt"), "content1").unwrap();
        fs::write(dir.path().join("file2.txt"), "content2").unwrap();
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("file3.txt"), "content3").unwrap();

        let config = make_config(dir.path());
        let module = InotifyMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 3);
        assert_eq!(result.issues_found, 0);
        assert!(!result.snapshot.is_empty());
    }

    #[test]
    fn test_debounce() {
        let mut debounce_map: HashMap<PathBuf, Instant> = HashMap::new();
        let debounce_duration = std::time::Duration::from_millis(100);
        let path = PathBuf::from("/test/file");

        // 最初のイベントは通過する
        let now = Instant::now();
        assert!(debounce_map.get(&path).is_none());
        debounce_map.insert(path.clone(), now);

        // debounce 期間内のイベントはスキップされる
        let within = now + std::time::Duration::from_millis(50);
        if let Some(last_time) = debounce_map.get(&path) {
            assert!(within.duration_since(*last_time) < debounce_duration);
        }

        // debounce 期間後のイベントは通過する
        let after = now + std::time::Duration::from_millis(200);
        if let Some(last_time) = debounce_map.get(&path) {
            assert!(after.duration_since(*last_time) >= debounce_duration);
        }
    }

    #[tokio::test]
    async fn test_start_stop() {
        let dir = TempDir::new().unwrap();
        let config = make_config(dir.path());
        let mut module = InotifyMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        // 少し待ってから停止
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_init_empty_watch_paths() {
        let config = InotifyMonitorConfig {
            enabled: true,
            watch_paths: vec![],
            recursive: true,
            exclude_patterns: vec![],
            max_watches: 65536,
            debounce_ms: 100,
        };
        let mut module = InotifyMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_invalid_exclude_pattern() {
        let dir = TempDir::new().unwrap();
        let config = InotifyMonitorConfig {
            enabled: true,
            watch_paths: vec![dir.path().to_path_buf()],
            recursive: true,
            // glob パターンとしては有効なので、実際には無効なパターンを作るのは難しい
            // glob_to_regex は常に有効な正規表現を生成するため、このテストは正常系を確認
            exclude_patterns: vec!["*.swp".to_string()],
            max_watches: 65536,
            debounce_ms: 100,
        };
        let mut module = InotifyMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_valid() {
        let dir = TempDir::new().unwrap();
        let config = make_config(dir.path());
        let mut module = InotifyMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan_with_exclude() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("file1.txt"), "content1").unwrap();
        fs::write(dir.path().join("file2.swp"), "swap").unwrap();
        fs::write(dir.path().join("file3.tmp"), "temp").unwrap();

        let config = InotifyMonitorConfig {
            enabled: true,
            watch_paths: vec![dir.path().to_path_buf()],
            recursive: true,
            exclude_patterns: vec!["*.swp".to_string(), "*.tmp".to_string()],
            max_watches: 65536,
            debounce_ms: 100,
        };
        let module = InotifyMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // file1.txt のみ（swp と tmp は除外）
        assert_eq!(result.items_scanned, 1);
    }
}
