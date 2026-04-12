//! 動的ライブラリインジェクション検知モジュール
//!
//! `/proc/[pid]/maps` を定期スキャンし、ベースラインとの差分で
//! 不審な共有ライブラリの動的ロードを検知する。
//!
//! 検知対象:
//! - 新たにロードされた共有ライブラリ（ベースラインとの差分）
//! - 削除済みファイルからのライブラリロード（`(deleted)` マーカー）
//! - 不審なパスからのライブラリロード（`/tmp`, `/dev/shm`, `/var/tmp` 等）

use crate::config::DynamicLibraryMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use tokio_util::sync::CancellationToken;

/// 動的ライブラリインジェクション検知モジュール
///
/// `/proc/[pid]/maps` をベースライン差分方式で定期スキャンし、
/// 不審な共有ライブラリの動的ロードを検知する。
pub struct DynamicLibraryMonitorModule {
    config: DynamicLibraryMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

/// 実行中のプロセス PID 一覧を `/proc` から取得する
fn list_pids() -> Vec<u32> {
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name_str = name.to_str()?;
            name_str.parse::<u32>().ok()
        })
        .collect()
}

/// `/proc/[pid]/comm` からプロセス名を取得する
fn get_process_name(pid: u32) -> String {
    let comm_path = format!("/proc/{pid}/comm");
    std::fs::read_to_string(&comm_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// `/proc/[pid]/status` の Uid 行から実効 UID を取得する
fn get_process_uid(pid: u32) -> Option<u32> {
    let status_path = format!("/proc/{pid}/status");
    let content = std::fs::read_to_string(&status_path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Uid: real effective saved filesystem
            let mut fields = rest.split_whitespace();
            let _real = fields.next();
            let effective = fields.next()?;
            return effective.parse::<u32>().ok();
        }
    }
    None
}

/// パス名が共有ライブラリかどうかを判定する
///
/// `.so` を含み、`[` で始まらず、空でないパスを共有ライブラリとみなす。
fn is_shared_library(pathname: &str) -> bool {
    if pathname.is_empty() || pathname.starts_with('[') {
        return false;
    }
    pathname.contains(".so")
}

/// `/proc/[pid]/maps` を読み、共有ライブラリのパス名集合を返す
///
/// `(deleted)` サフィックス付きのパスもそのまま含む。
fn extract_libraries(pid: u32) -> HashSet<String> {
    let maps_path = format!("/proc/{pid}/maps");
    let content = match std::fs::read_to_string(&maps_path) {
        Ok(c) => c,
        Err(_) => return HashSet::new(),
    };

    let mut libs = HashSet::new();
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        // address perms offset dev inode [pathname...]
        let _address = fields.next();
        let _perms = fields.next();
        let _offset = fields.next();
        let _dev = fields.next();
        let _inode = fields.next();
        let pathname: String = fields.collect::<Vec<&str>>().join(" ");

        if !pathname.is_empty() {
            let clean = clean_path(&pathname);
            if is_shared_library(clean) {
                libs.insert(pathname);
            }
        }
    }
    libs
}

/// ignore_libraries パターンのリストを正規表現にコンパイルする
fn compile_ignore_patterns(patterns: &[String]) -> Result<Vec<Regex>, AppError> {
    patterns
        .iter()
        .map(|p| {
            Regex::new(p).map_err(|e| AppError::ModuleConfig {
                message: format!("ignore_libraries の正規表現が不正です: {p}: {e}"),
            })
        })
        .collect()
}

/// パスが除外パターンのいずれかに一致するかを判定する
fn is_ignored(path: &str, patterns: &[Regex]) -> bool {
    patterns.iter().any(|re| re.is_match(path))
}

/// パスが `(deleted)` サフィックスで終わるかを判定する
fn is_deleted(path: &str) -> bool {
    path.ends_with("(deleted)")
}

/// パスから ` (deleted)` サフィックスを除去する
fn clean_path(path: &str) -> &str {
    path.strip_suffix(" (deleted)").unwrap_or(path)
}

/// パスが不審なパスリストのいずれかで始まるかを判定する
fn is_suspicious_path(path: &str, suspicious_paths: &[String]) -> bool {
    let clean = clean_path(path);
    suspicious_paths
        .iter()
        .any(|sp| clean.starts_with(sp.as_str()))
}

impl DynamicLibraryMonitorModule {
    /// 新しい動的ライブラリインジェクション検知モジュールを作成する
    pub fn new(config: DynamicLibraryMonitorConfig, event_bus: Option<EventBus>) -> Self {
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
}

impl Module for DynamicLibraryMonitorModule {
    fn name(&self) -> &str {
        "dynamic_library_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        // ignore_libraries パターンのコンパイル検証
        compile_ignore_patterns(&self.config.ignore_libraries)?;

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            suspicious_paths = ?self.config.suspicious_paths,
            ignore_pids_count = self.config.ignore_pids.len(),
            ignore_libraries_count = self.config.ignore_libraries.len(),
            monitor_all_processes = self.config.monitor_all_processes,
            "動的ライブラリインジェクション検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let ignore_patterns = compile_ignore_patterns(&config.ignore_libraries)?;

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(config.scan_interval_secs));
            interval.tick().await;

            let mut baseline: HashMap<u32, HashSet<String>> = HashMap::new();

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("動的ライブラリインジェクション検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let pids = list_pids();
                        let current_pids: HashSet<u32> = pids.iter().copied().collect();

                        for &pid in &pids {
                            // ignore_pids をスキップ
                            if config.ignore_pids.contains(&pid) {
                                continue;
                            }

                            // monitor_all_processes=false なら UID=0 のプロセスのみ
                            if !config.monitor_all_processes {
                                match get_process_uid(pid) {
                                    Some(0) => {}
                                    _ => continue,
                                }
                            }

                            let libs = extract_libraries(pid);

                            if let Some(prev) = baseline.get(&pid) {
                                // 差分で新規ライブラリを検出
                                let new_libs: Vec<&String> = libs.difference(prev).collect();
                                for lib in new_libs {
                                    if is_ignored(clean_path(lib), &ignore_patterns) {
                                        continue;
                                    }

                                    let process_name = get_process_name(pid);
                                    let details = format!(
                                        "pid={}, process={}, library={}",
                                        pid, process_name, lib
                                    );

                                    if is_deleted(lib) {
                                        tracing::error!(
                                            pid = pid,
                                            process = %process_name,
                                            library = %lib,
                                            "削除済みファイルからの動的ライブラリロードを検出しました"
                                        );
                                        if let Some(bus) = &event_bus {
                                            bus.publish(
                                                SecurityEvent::new(
                                                    "dynamic_library_deleted_loaded",
                                                    Severity::Critical,
                                                    "dynamic_library_monitor",
                                                    format!(
                                                        "PID {} ({}) で削除済みファイルからのライブラリロードを検出: {}",
                                                        pid, process_name, lib
                                                    ),
                                                )
                                                .with_details(details),
                                            );
                                        }
                                    } else if is_suspicious_path(lib, &config.suspicious_paths) {
                                        tracing::warn!(
                                            pid = pid,
                                            process = %process_name,
                                            library = %lib,
                                            "不審なパスからの動的ライブラリロードを検出しました"
                                        );
                                        if let Some(bus) = &event_bus {
                                            bus.publish(
                                                SecurityEvent::new(
                                                    "dynamic_library_suspicious_path",
                                                    Severity::Warning,
                                                    "dynamic_library_monitor",
                                                    format!(
                                                        "PID {} ({}) で不審なパスからのライブラリロードを検出: {}",
                                                        pid, process_name, lib
                                                    ),
                                                )
                                                .with_details(details),
                                            );
                                        }
                                    } else {
                                        tracing::warn!(
                                            pid = pid,
                                            process = %process_name,
                                            library = %lib,
                                            "新規の動的ライブラリロードを検出しました"
                                        );
                                        if let Some(bus) = &event_bus {
                                            bus.publish(
                                                SecurityEvent::new(
                                                    "dynamic_library_new_loaded",
                                                    Severity::Warning,
                                                    "dynamic_library_monitor",
                                                    format!(
                                                        "PID {} ({}) で新規ライブラリロードを検出: {}",
                                                        pid, process_name, lib
                                                    ),
                                                )
                                                .with_details(details),
                                            );
                                        }
                                    }
                                }
                            }

                            // ベースラインを更新（新規プロセスも含む）
                            baseline.insert(pid, libs);
                        }

                        // 消滅した PID をベースラインから削除
                        baseline.retain(|pid, _| current_pids.contains(pid));

                        tracing::debug!("動的ライブラリスキャン完了: 監視中プロセス数={}", baseline.len());
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
        let start = std::time::Instant::now();

        let pids = list_pids();
        let mut items_scanned = 0;
        let mut issues_found = 0;
        let mut scan_snapshot: BTreeMap<String, String> = BTreeMap::new();

        for pid in &pids {
            let libs = extract_libraries(*pid);
            if libs.is_empty() {
                continue;
            }

            items_scanned += 1;
            let process_name = get_process_name(*pid);

            for lib in &libs {
                let clean = clean_path(lib);
                let key = format!("{}:{}:{}", pid, process_name, clean);

                if is_deleted(lib) {
                    issues_found += 1;
                    scan_snapshot.insert(key, format!("{} (deleted)", clean));
                } else if is_suspicious_path(lib, &self.config.suspicious_paths) {
                    issues_found += 1;
                    scan_snapshot.insert(key, format!("{} (suspicious)", clean));
                } else {
                    scan_snapshot.insert(key, clean.to_string());
                }
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "{}件のプロセスをスキャンし、{}件の不審な動的ライブラリを検出しました",
                items_scanned, issues_found
            ),
            snapshot: scan_snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> DynamicLibraryMonitorConfig {
        DynamicLibraryMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            suspicious_paths: vec![
                "/tmp".to_string(),
                "/dev/shm".to_string(),
                "/var/tmp".to_string(),
            ],
            ignore_pids: Vec::new(),
            ignore_libraries: Vec::new(),
            monitor_all_processes: true,
        }
    }

    #[test]
    fn test_is_shared_library() {
        assert!(is_shared_library("/usr/lib/libc.so.6"));
        assert!(is_shared_library("/lib/x86_64-linux-gnu/libm.so"));
        assert!(!is_shared_library("[stack]"));
        assert!(!is_shared_library("[heap]"));
        assert!(!is_shared_library(""));
        assert!(!is_shared_library("/usr/bin/bash"));
    }

    #[test]
    fn test_is_shared_library_versioned() {
        assert!(is_shared_library("libc.so.6"));
        assert!(is_shared_library("/usr/lib/libssl.so.3"));
        assert!(is_shared_library("/lib/ld-linux-x86-64.so.2"));
    }

    #[test]
    fn test_is_deleted() {
        assert!(is_deleted("/tmp/evil.so (deleted)"));
        assert!(!is_deleted("/usr/lib/libc.so.6"));
        assert!(!is_deleted(""));
    }

    #[test]
    fn test_clean_path() {
        assert_eq!(clean_path("/tmp/evil.so (deleted)"), "/tmp/evil.so");
        assert_eq!(clean_path("/usr/lib/libc.so.6"), "/usr/lib/libc.so.6");
        assert_eq!(clean_path(""), "");
    }

    #[test]
    fn test_is_suspicious_path() {
        let suspicious = vec![
            "/tmp".to_string(),
            "/dev/shm".to_string(),
            "/var/tmp".to_string(),
        ];
        assert!(is_suspicious_path("/tmp/evil.so", &suspicious));
        assert!(is_suspicious_path("/dev/shm/inject.so", &suspicious));
        assert!(is_suspicious_path("/var/tmp/lib.so", &suspicious));
        assert!(!is_suspicious_path("/usr/lib/libc.so.6", &suspicious));
        assert!(!is_suspicious_path(
            "/lib/x86_64-linux-gnu/libm.so",
            &suspicious
        ));
    }

    #[test]
    fn test_compile_ignore_patterns() {
        let patterns = vec!["^/usr/lib/.*".to_string(), "libc\\.so".to_string()];
        let result = compile_ignore_patterns(&patterns);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_is_ignored() {
        let patterns = vec!["^/usr/lib/.*".to_string(), "libc\\.so".to_string()];
        let compiled = compile_ignore_patterns(&patterns).unwrap();
        assert!(is_ignored("/usr/lib/libfoo.so", &compiled));
        assert!(is_ignored("/some/path/libc.so.6", &compiled));
        assert!(!is_ignored("/tmp/evil.so", &compiled));
    }

    #[test]
    fn test_invalid_regex_in_init() {
        let mut config = default_config();
        config.ignore_libraries = vec!["[invalid".to_string()];
        let mut module = DynamicLibraryMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = default_config();
        config.scan_interval_secs = 0;
        let mut module = DynamicLibraryMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = default_config();
        let mut module = DynamicLibraryMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut config = default_config();
        config.scan_interval_secs = 3600;
        let mut module = DynamicLibraryMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = default_config();
        let module = DynamicLibraryMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // 少なくとも現在のプロセスがスキャンされるはず
        assert!(result.items_scanned > 0);
    }

    #[test]
    fn test_module_name() {
        let config = default_config();
        let module = DynamicLibraryMonitorModule::new(config, None);
        assert_eq!(module.name(), "dynamic_library_monitor");
    }

    #[test]
    fn test_list_pids() {
        let pids = list_pids();
        assert!(!pids.is_empty());
    }

    #[test]
    fn test_extract_libraries_current_process() {
        let pid = std::process::id();
        let libs = extract_libraries(pid);
        // 現在のプロセスにはいくつかの共有ライブラリがロードされているはず
        assert!(!libs.is_empty());
    }

    #[test]
    fn test_extract_libraries_nonexistent() {
        let libs = extract_libraries(u32::MAX);
        assert!(libs.is_empty());
    }
}
