//! プロセスツリー監視モジュール
//!
//! /proc を走査してプロセスの親子関係を分析し、
//! 不審なプロセスツリーパターンを検知する。
//!
//! 検知対象:
//! - 不審な親子関係（Web サーバからのシェル起動など）
//! - 異常に深いプロセスチェーン（フォーク爆弾等の兆候）

use crate::config::ProcessTreeMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// プロセス情報
#[derive(Debug, Clone)]
struct ProcessInfo {
    /// プロセス ID
    pid: u32,
    /// 親プロセス ID
    ppid: u32,
    /// プロセス名（comm）
    comm: String,
    /// 実行ファイルパス（取得できない場合は None）
    exe_path: Option<String>,
}

/// コンパイル済みの不審パターン（親正規表現, 子正規表現, 説明）
type CompiledPattern = (Regex, Regex, String);

/// プロセスツリー監視モジュール
///
/// /proc を定期スキャンし、不審な親子関係や異常に深いプロセスチェーンを検知する。
pub struct ProcessTreeMonitorModule {
    config: ProcessTreeMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl ProcessTreeMonitorModule {
    /// 新しいプロセスツリー監視モジュールを作成する
    pub fn new(config: ProcessTreeMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// /proc を走査して全プロセス情報を収集する
    fn scan_processes() -> HashMap<u32, ProcessInfo> {
        let mut processes = HashMap::new();

        let proc_dir = match std::fs::read_dir("/proc") {
            Ok(dir) => dir,
            Err(err) => {
                tracing::debug!(error = %err, "/proc の読み取りに失敗しました");
                return processes;
            }
        };

        for entry in proc_dir.filter_map(|e| e.ok()) {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            // PID ディレクトリのみ対象
            let pid: u32 = match name.parse() {
                Ok(pid) => pid,
                Err(_) => continue,
            };

            // comm の取得
            let comm_path = format!("/proc/{pid}/comm");
            let comm = match std::fs::read_to_string(&comm_path) {
                Ok(c) => c.trim().to_string(),
                Err(_) => continue,
            };

            // ppid の取得（/proc/[pid]/status から）
            let status_path = format!("/proc/{pid}/status");
            let ppid = match std::fs::read_to_string(&status_path) {
                Ok(status) => {
                    let mut ppid_val = 0u32;
                    for line in status.lines() {
                        if let Some(val) = line.strip_prefix("PPid:\t") {
                            ppid_val = val.trim().parse().unwrap_or(0);
                            break;
                        }
                    }
                    ppid_val
                }
                Err(_) => continue,
            };

            // exe_path の取得（readlink）
            let exe_link = format!("/proc/{pid}/exe");
            let exe_path = std::fs::read_link(&exe_link)
                .ok()
                .map(|p| p.to_string_lossy().to_string());

            processes.insert(
                pid,
                ProcessInfo {
                    pid,
                    ppid,
                    comm,
                    exe_path,
                },
            );
        }

        processes
    }

    /// 不審な親子関係パターンをチェックする
    fn check_suspicious_patterns(
        processes: &HashMap<u32, ProcessInfo>,
        compiled_patterns: &[CompiledPattern],
        whitelist_paths: &[PathBuf],
    ) -> Vec<(u32, u32, String)> {
        let mut results = Vec::new();

        for process in processes.values() {
            // ホワイトリスト該当プロセスはスキップ
            if Self::is_whitelisted(process, whitelist_paths) {
                continue;
            }

            // 親プロセスを取得
            let parent = match processes.get(&process.ppid) {
                Some(p) => p,
                None => continue,
            };

            for (parent_re, child_re, description) in compiled_patterns {
                if parent_re.is_match(&parent.comm) && child_re.is_match(&process.comm) {
                    results.push((process.pid, parent.pid, description.clone()));
                }
            }
        }

        results
    }

    /// 異常に深いプロセスチェーンをチェックする
    fn check_deep_chains(
        processes: &HashMap<u32, ProcessInfo>,
        max_depth: usize,
        whitelist_paths: &[PathBuf],
    ) -> Vec<(u32, usize)> {
        let mut results = Vec::new();

        for process in processes.values() {
            if Self::is_whitelisted(process, whitelist_paths) {
                continue;
            }

            let depth = Self::compute_chain_depth(processes, process.pid);
            if depth > max_depth {
                results.push((process.pid, depth));
            }
        }

        results
    }

    /// プロセスチェーンの深さを計算する
    fn compute_chain_depth(processes: &HashMap<u32, ProcessInfo>, start_pid: u32) -> usize {
        let mut depth = 0;
        let mut current_pid = start_pid;
        let mut visited = HashSet::new();

        while let Some(process) = processes.get(&current_pid) {
            if !visited.insert(current_pid) {
                // ループ検出 — 無限ループを防止
                break;
            }
            if process.ppid == 0 || process.ppid == current_pid {
                break;
            }
            current_pid = process.ppid;
            depth += 1;
        }

        depth
    }

    /// プロセスがホワイトリストに該当するかチェックする
    fn is_whitelisted(process: &ProcessInfo, whitelist_paths: &[PathBuf]) -> bool {
        if let Some(exe_path) = &process.exe_path {
            let exe = PathBuf::from(exe_path);
            for wl_path in whitelist_paths {
                if exe.starts_with(wl_path) {
                    return true;
                }
            }
        }
        false
    }

    /// suspicious_patterns の正規表現をコンパイルする
    fn compile_patterns(
        config: &ProcessTreeMonitorConfig,
    ) -> Result<Vec<CompiledPattern>, AppError> {
        let mut compiled = Vec::new();
        for pattern in &config.suspicious_patterns {
            let parent_re = Regex::new(&pattern.parent).map_err(|e| AppError::ModuleConfig {
                message: format!(
                    "不審パターンの親正規表現が無効です: '{}': {}",
                    pattern.parent, e
                ),
            })?;
            let child_re = Regex::new(&pattern.child).map_err(|e| AppError::ModuleConfig {
                message: format!(
                    "不審パターンの子正規表現が無効です: '{}': {}",
                    pattern.child, e
                ),
            })?;
            compiled.push((parent_re, child_re, pattern.description.clone()));
        }
        Ok(compiled)
    }
}

impl Module for ProcessTreeMonitorModule {
    fn name(&self) -> &str {
        "process_tree_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.max_depth == 0 {
            return Err(AppError::ModuleConfig {
                message: "max_depth は 0 より大きい値を指定してください".to_string(),
            });
        }

        // 正規表現のコンパイルテスト
        Self::compile_patterns(&self.config)?;

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            max_depth = self.config.max_depth,
            pattern_count = self.config.suspicious_patterns.len(),
            whitelist_count = self.config.whitelist_paths.len(),
            "プロセスツリー監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let compiled_patterns = Self::compile_patterns(&self.config)?;

        let scan_interval_secs = self.config.scan_interval_secs;
        let max_depth = self.config.max_depth;
        let whitelist_paths = self.config.whitelist_paths.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            // 重複アラート防止用セット: (pid, description)
            let mut known_alerts: HashSet<(u32, String)> = HashSet::new();

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("プロセスツリー監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let processes = ProcessTreeMonitorModule::scan_processes();

                        // 現存PIDセットで known_alerts をクリーンアップ
                        let current_pids: HashSet<u32> = processes.keys().copied().collect();
                        known_alerts.retain(|(pid, _)| current_pids.contains(pid));

                        // 不審パターンチェック
                        let suspicious = ProcessTreeMonitorModule::check_suspicious_patterns(
                            &processes,
                            &compiled_patterns,
                            &whitelist_paths,
                        );
                        for (child_pid, parent_pid, description) in &suspicious {
                            let alert_key = (*child_pid, description.clone());
                            if known_alerts.insert(alert_key) {
                                let child_comm = processes.get(child_pid)
                                    .map(|p| p.comm.as_str())
                                    .unwrap_or("unknown");
                                let parent_comm = processes.get(parent_pid)
                                    .map(|p| p.comm.as_str())
                                    .unwrap_or("unknown");

                                tracing::warn!(
                                    child_pid = child_pid,
                                    parent_pid = parent_pid,
                                    child_comm = child_comm,
                                    parent_comm = parent_comm,
                                    description = description.as_str(),
                                    "不審なプロセスツリーパターンを検知しました"
                                );

                                if let Some(bus) = &event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "process_tree_suspicious_pattern",
                                            Severity::Warning,
                                            "process_tree_monitor",
                                            "不審なプロセスツリーパターンを検知しました",
                                        )
                                        .with_details(format!(
                                            "{}: {} (pid={}) -> {} (pid={})",
                                            description, parent_comm, parent_pid, child_comm, child_pid
                                        )),
                                    );
                                }
                            }
                        }

                        // 深いチェーンチェック
                        let deep_chains = ProcessTreeMonitorModule::check_deep_chains(
                            &processes,
                            max_depth,
                            &whitelist_paths,
                        );
                        for (pid, depth) in &deep_chains {
                            let alert_key = (*pid, format!("deep_chain_{depth}"));
                            if known_alerts.insert(alert_key) {
                                let comm = processes.get(pid)
                                    .map(|p| p.comm.as_str())
                                    .unwrap_or("unknown");

                                tracing::warn!(
                                    pid = pid,
                                    depth = depth,
                                    comm = comm,
                                    max_depth = max_depth,
                                    "異常に深いプロセスチェーンを検知しました"
                                );

                                if let Some(bus) = &event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "process_tree_deep_chain",
                                            Severity::Warning,
                                            "process_tree_monitor",
                                            "異常に深いプロセスチェーンを検知しました",
                                        )
                                        .with_details(format!(
                                            "{} (pid={}) の深度が {} (最大: {})",
                                            comm, pid, depth, max_depth
                                        )),
                                    );
                                }
                            }
                        }

                        tracing::debug!(
                            process_count = processes.len(),
                            suspicious_count = suspicious.len(),
                            deep_chain_count = deep_chains.len(),
                            "プロセスツリースキャンが完了しました"
                        );
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

        let processes = Self::scan_processes();
        let compiled_patterns = Self::compile_patterns(&self.config)?;

        let suspicious = Self::check_suspicious_patterns(
            &processes,
            &compiled_patterns,
            &self.config.whitelist_paths,
        );
        let deep_chains = Self::check_deep_chains(
            &processes,
            self.config.max_depth,
            &self.config.whitelist_paths,
        );

        let issues_found = suspicious.len() + deep_chains.len();
        let items_scanned = processes.len();
        let duration = start.elapsed();

        let snapshot: BTreeMap<String, String> = processes
            .iter()
            .map(|(pid, info)| {
                (
                    pid.to_string(),
                    format!(
                        "comm={},ppid={},exe={}",
                        info.comm,
                        info.ppid,
                        info.exe_path.as_deref().unwrap_or("unknown")
                    ),
                )
            })
            .collect();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "プロセスツリーから {}件のプロセスをスキャンし、{}件の問題を検出しました",
                items_scanned, issues_found
            ),
            snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SuspiciousTreePattern;

    fn make_config() -> ProcessTreeMonitorConfig {
        ProcessTreeMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            max_depth: 10,
            suspicious_patterns: vec![SuspiciousTreePattern {
                parent: "nginx|httpd|apache2".to_string(),
                child: "sh|bash|dash|zsh|fish".to_string(),
                description: "Web サーバからのシェル起動".to_string(),
            }],
            whitelist_paths: vec![],
        }
    }

    #[test]
    fn test_scan_processes() {
        let processes = ProcessTreeMonitorModule::scan_processes();
        // 自プロセスが含まれることを確認
        let my_pid = std::process::id();
        assert!(
            processes.contains_key(&my_pid),
            "自プロセス（PID={}）がスキャン結果に含まれるべき",
            my_pid
        );
    }

    #[test]
    fn test_compute_chain_depth() {
        let mut processes = HashMap::new();
        // PID 1 (root) -> PID 2 -> PID 3 -> PID 4
        processes.insert(
            1,
            ProcessInfo {
                pid: 1,
                ppid: 0,
                comm: "init".to_string(),
                exe_path: None,
            },
        );
        processes.insert(
            2,
            ProcessInfo {
                pid: 2,
                ppid: 1,
                comm: "parent".to_string(),
                exe_path: None,
            },
        );
        processes.insert(
            3,
            ProcessInfo {
                pid: 3,
                ppid: 2,
                comm: "child".to_string(),
                exe_path: None,
            },
        );
        processes.insert(
            4,
            ProcessInfo {
                pid: 4,
                ppid: 3,
                comm: "grandchild".to_string(),
                exe_path: None,
            },
        );

        assert_eq!(
            ProcessTreeMonitorModule::compute_chain_depth(&processes, 1),
            0
        );
        assert_eq!(
            ProcessTreeMonitorModule::compute_chain_depth(&processes, 2),
            1
        );
        assert_eq!(
            ProcessTreeMonitorModule::compute_chain_depth(&processes, 3),
            2
        );
        assert_eq!(
            ProcessTreeMonitorModule::compute_chain_depth(&processes, 4),
            3
        );
    }

    #[test]
    fn test_compute_chain_depth_loop_prevention() {
        let mut processes = HashMap::new();
        // ループ: PID 1 -> PID 2 -> PID 1
        processes.insert(
            1,
            ProcessInfo {
                pid: 1,
                ppid: 2,
                comm: "a".to_string(),
                exe_path: None,
            },
        );
        processes.insert(
            2,
            ProcessInfo {
                pid: 2,
                ppid: 1,
                comm: "b".to_string(),
                exe_path: None,
            },
        );

        // ループで無限にならないことを確認
        let depth = ProcessTreeMonitorModule::compute_chain_depth(&processes, 1);
        assert!(depth <= 2);
    }

    #[test]
    fn test_check_suspicious_patterns() {
        let mut processes = HashMap::new();
        processes.insert(
            100,
            ProcessInfo {
                pid: 100,
                ppid: 0,
                comm: "nginx".to_string(),
                exe_path: Some("/usr/sbin/nginx".to_string()),
            },
        );
        processes.insert(
            200,
            ProcessInfo {
                pid: 200,
                ppid: 100,
                comm: "bash".to_string(),
                exe_path: Some("/bin/bash".to_string()),
            },
        );

        let compiled = vec![(
            Regex::new("nginx|httpd|apache2").unwrap(),
            Regex::new("sh|bash|dash|zsh|fish").unwrap(),
            "Web サーバからのシェル起動".to_string(),
        )];

        let results =
            ProcessTreeMonitorModule::check_suspicious_patterns(&processes, &compiled, &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 200); // child pid
        assert_eq!(results[0].1, 100); // parent pid
    }

    #[test]
    fn test_check_suspicious_patterns_no_match() {
        let mut processes = HashMap::new();
        processes.insert(
            100,
            ProcessInfo {
                pid: 100,
                ppid: 0,
                comm: "systemd".to_string(),
                exe_path: None,
            },
        );
        processes.insert(
            200,
            ProcessInfo {
                pid: 200,
                ppid: 100,
                comm: "bash".to_string(),
                exe_path: None,
            },
        );

        let compiled = vec![(
            Regex::new("nginx|httpd|apache2").unwrap(),
            Regex::new("sh|bash|dash|zsh|fish").unwrap(),
            "Web サーバからのシェル起動".to_string(),
        )];

        let results =
            ProcessTreeMonitorModule::check_suspicious_patterns(&processes, &compiled, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_check_deep_chains() {
        let mut processes = HashMap::new();
        // 深さ 5 のチェーン: 1 -> 2 -> 3 -> 4 -> 5 -> 6
        for i in 1..=6u32 {
            processes.insert(
                i,
                ProcessInfo {
                    pid: i,
                    ppid: if i == 1 { 0 } else { i - 1 },
                    comm: format!("proc{i}"),
                    exe_path: None,
                },
            );
        }

        // max_depth=3 で深さ 4,5 が検知される
        let results = ProcessTreeMonitorModule::check_deep_chains(&processes, 3, &[]);
        assert!(!results.is_empty());
        // PID 5 (depth=4) と PID 6 (depth=5) が検知されるはず
        let deep_pids: HashSet<u32> = results.iter().map(|(pid, _)| *pid).collect();
        assert!(deep_pids.contains(&5));
        assert!(deep_pids.contains(&6));
    }

    #[test]
    fn test_is_whitelisted() {
        let process = ProcessInfo {
            pid: 100,
            ppid: 1,
            comm: "myapp".to_string(),
            exe_path: Some("/opt/myapp/bin/myapp".to_string()),
        };

        assert!(ProcessTreeMonitorModule::is_whitelisted(
            &process,
            &[PathBuf::from("/opt/myapp")]
        ));
        assert!(!ProcessTreeMonitorModule::is_whitelisted(
            &process,
            &[PathBuf::from("/usr/local")]
        ));
    }

    #[test]
    fn test_is_whitelisted_no_exe_path() {
        let process = ProcessInfo {
            pid: 100,
            ppid: 1,
            comm: "myapp".to_string(),
            exe_path: None,
        };

        assert!(!ProcessTreeMonitorModule::is_whitelisted(
            &process,
            &[PathBuf::from("/opt/myapp")]
        ));
    }

    #[test]
    fn test_init_zero_interval() {
        let config = ProcessTreeMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            max_depth: 10,
            suspicious_patterns: vec![],
            whitelist_paths: vec![],
        };
        let mut module = ProcessTreeMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_zero_depth() {
        let config = ProcessTreeMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            max_depth: 0,
            suspicious_patterns: vec![],
            whitelist_paths: vec![],
        };
        let mut module = ProcessTreeMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_invalid_regex() {
        let config = ProcessTreeMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            max_depth: 10,
            suspicious_patterns: vec![SuspiciousTreePattern {
                parent: "[invalid".to_string(),
                child: "bash".to_string(),
                description: "invalid pattern".to_string(),
            }],
            whitelist_paths: vec![],
        };
        let mut module = ProcessTreeMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = make_config();
        let mut module = ProcessTreeMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = ProcessTreeMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            max_depth: 10,
            suspicious_patterns: vec![],
            whitelist_paths: vec![],
        };
        let mut module = ProcessTreeMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = make_config();
        let module = ProcessTreeMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert!(
            result.items_scanned > 0,
            "プロセスが1つ以上スキャンされるべき"
        );
    }

    #[test]
    fn test_check_suspicious_patterns_whitelisted() {
        let mut processes = HashMap::new();
        processes.insert(
            100,
            ProcessInfo {
                pid: 100,
                ppid: 0,
                comm: "nginx".to_string(),
                exe_path: Some("/usr/sbin/nginx".to_string()),
            },
        );
        processes.insert(
            200,
            ProcessInfo {
                pid: 200,
                ppid: 100,
                comm: "bash".to_string(),
                exe_path: Some("/opt/allowed/bin/bash".to_string()),
            },
        );

        let compiled = vec![(
            Regex::new("nginx|httpd|apache2").unwrap(),
            Regex::new("sh|bash|dash|zsh|fish").unwrap(),
            "Web サーバからのシェル起動".to_string(),
        )];

        let results = ProcessTreeMonitorModule::check_suspicious_patterns(
            &processes,
            &compiled,
            &[PathBuf::from("/opt/allowed")],
        );
        assert!(
            results.is_empty(),
            "ホワイトリスト該当プロセスは除外されるべき"
        );
    }

    #[test]
    fn test_check_deep_chains_whitelisted() {
        let mut processes = HashMap::new();
        for i in 1..=6u32 {
            processes.insert(
                i,
                ProcessInfo {
                    pid: i,
                    ppid: if i == 1 { 0 } else { i - 1 },
                    comm: format!("proc{i}"),
                    exe_path: Some(format!("/opt/safe/bin/proc{i}")),
                },
            );
        }

        let results = ProcessTreeMonitorModule::check_deep_chains(
            &processes,
            3,
            &[PathBuf::from("/opt/safe")],
        );
        assert!(
            results.is_empty(),
            "ホワイトリスト該当プロセスは除外されるべき"
        );
    }
}
