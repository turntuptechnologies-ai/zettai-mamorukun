//! ptrace 検知モジュール
//!
//! `/proc/[pid]/status` の `TracerPid` フィールドを定期的に監視し、
//! プロセスが ptrace でアタッチされている（デバッガ注入の可能性）ことを検知する。
//!
//! 検知対象:
//! - `TracerPid` が 0 以外のプロセス（ptrace アタッチされている）
//! - ホワイトリストに含まれないトレーサーによるアタッチ

use crate::config::PtraceMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

/// ptrace 検知結果
#[derive(Debug, Clone)]
struct PtraceFinding {
    /// トレースされているプロセスの PID
    pid: u32,
    /// トレースされているプロセスの名前
    process_name: String,
    /// トレーサーの PID
    tracer_pid: u32,
    /// トレーサーのプロセス名
    tracer_name: String,
}

/// ptrace 検知モジュール
///
/// `/proc/[pid]/status` の `TracerPid` を定期スキャンし、
/// 不正な ptrace アタッチを検知する。
pub struct PtraceMonitorModule {
    config: PtraceMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl PtraceMonitorModule {
    /// 新しい ptrace 検知モジュールを作成する
    pub fn new(config: PtraceMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// プロセス名を取得する
    fn get_process_name(pid: u32) -> String {
        let comm_path = format!("/proc/{pid}/comm");
        std::fs::read_to_string(&comm_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    /// 実行中のプロセス PID 一覧を取得する
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

    /// `/proc/[pid]/status` から `TracerPid` を取得する
    ///
    /// `TracerPid` が 0 の場合（トレースされていない）は `None` を返す。
    /// ファイル読み取り失敗時も `None` を返す。
    fn get_tracer_pid(pid: u32) -> Option<u32> {
        let status_path = format!("/proc/{pid}/status");
        let content = std::fs::read_to_string(&status_path).ok()?;

        for line in content.lines() {
            if let Some(value) = line.strip_prefix("TracerPid:") {
                let tracer_pid: u32 = value.trim().parse().ok()?;
                if tracer_pid != 0 {
                    return Some(tracer_pid);
                }
                return None;
            }
        }

        None
    }

    /// 全プロセスをスキャンし、ptrace アタッチされているプロセスを検出する
    fn scan_all(config: &PtraceMonitorConfig) -> Vec<PtraceFinding> {
        let pids = Self::list_pids();
        let mut findings = Vec::new();

        for pid in pids {
            let Some(tracer_pid) = Self::get_tracer_pid(pid) else {
                continue;
            };

            let tracer_name = Self::get_process_name(tracer_pid);

            // ホワイトリストに含まれるトレーサーは除外
            if !tracer_name.is_empty() && config.whitelist_tracers.iter().any(|w| w == &tracer_name)
            {
                continue;
            }

            let process_name = Self::get_process_name(pid);

            // プロセス名が空の場合（既に終了している等）はスキップ
            if process_name.is_empty() {
                continue;
            }

            findings.push(PtraceFinding {
                pid,
                process_name,
                tracer_pid,
                tracer_name,
            });
        }

        findings
    }

    /// スキャン結果をイベントバスに発行する
    fn publish_findings(findings: &[PtraceFinding], event_bus: &Option<EventBus>) {
        for finding in findings {
            let message = format!(
                "PID {} ({}) が PID {} ({}) により ptrace アタッチされています",
                finding.pid, finding.process_name, finding.tracer_pid, finding.tracer_name
            );
            let details = format!(
                "pid={}, process={}, tracer_pid={}, tracer={}",
                finding.pid, finding.process_name, finding.tracer_pid, finding.tracer_name
            );

            tracing::warn!(
                pid = finding.pid,
                process = %finding.process_name,
                tracer_pid = finding.tracer_pid,
                tracer = %finding.tracer_name,
                "{}",
                message
            );

            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "ptrace_detected",
                        Severity::Critical,
                        "ptrace_monitor",
                        &message,
                    )
                    .with_details(details),
                );
            }
        }
    }
}

impl Module for PtraceMonitorModule {
    fn name(&self) -> &str {
        "ptrace_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            whitelist_tracers = ?self.config.whitelist_tracers,
            "ptrace 検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let config = self.config.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 初回スキャン
        let initial_findings = Self::scan_all(&config);
        tracing::info!(
            findings_count = initial_findings.len(),
            "初回 ptrace スキャンが完了しました"
        );
        Self::publish_findings(&initial_findings, &event_bus);

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(config.scan_interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ptrace 検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let findings = PtraceMonitorModule::scan_all(&config);
                        if findings.is_empty() {
                            tracing::debug!("ptrace アタッチは検出されませんでした");
                        } else {
                            PtraceMonitorModule::publish_findings(&findings, &event_bus);
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
        let start = std::time::Instant::now();

        let findings = Self::scan_all(&self.config);
        let pids = Self::list_pids();
        let items_scanned = pids.len();
        let issues_found = findings.len();

        let scan_snapshot: BTreeMap<String, String> = findings
            .iter()
            .map(|f| {
                (
                    format!("{}:{}", f.pid, f.process_name),
                    format!("tracer_pid={}, tracer={}", f.tracer_pid, f.tracer_name),
                )
            })
            .collect();

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "{}件のプロセスをスキャンし、{}件の ptrace アタッチを検出しました",
                items_scanned, issues_found
            ),
            snapshot: scan_snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> PtraceMonitorConfig {
        PtraceMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            whitelist_tracers: Vec::new(),
        }
    }

    // --- get_tracer_pid tests ---

    #[test]
    fn test_get_tracer_pid_current_process() {
        // 現在のプロセスは通常 ptrace されていないので None が返る
        let pid = std::process::id();
        let tracer = PtraceMonitorModule::get_tracer_pid(pid);
        assert!(tracer.is_none());
    }

    #[test]
    fn test_get_tracer_pid_nonexistent_pid() {
        let tracer = PtraceMonitorModule::get_tracer_pid(u32::MAX);
        assert!(tracer.is_none());
    }

    // --- get_process_name tests ---

    #[test]
    fn test_get_process_name_current_process() {
        let pid = std::process::id();
        let name = PtraceMonitorModule::get_process_name(pid);
        // テストバイナリのプロセス名が取得できるはず
        assert!(!name.is_empty());
    }

    #[test]
    fn test_get_process_name_nonexistent_pid() {
        let name = PtraceMonitorModule::get_process_name(u32::MAX);
        assert!(name.is_empty());
    }

    // --- list_pids tests ---

    #[test]
    fn test_list_pids_returns_entries() {
        let pids = PtraceMonitorModule::list_pids();
        // 最低でも PID 1（init）が存在するはず
        assert!(!pids.is_empty());
    }

    // --- scan_all tests ---

    #[test]
    fn test_scan_all_does_not_panic() {
        let config = default_config();
        let _findings = PtraceMonitorModule::scan_all(&config);
        // パニックしなければ OK
    }

    #[test]
    fn test_scan_all_with_whitelist() {
        let mut config = default_config();
        config.whitelist_tracers =
            vec!["gdb".to_string(), "strace".to_string(), "lldb".to_string()];
        let _findings = PtraceMonitorModule::scan_all(&config);
        // パニックしなければ OK
    }

    // --- Module trait tests ---

    #[test]
    fn test_module_name() {
        let config = default_config();
        let module = PtraceMonitorModule::new(config, None);
        assert_eq!(module.name(), "ptrace_monitor");
    }

    #[test]
    fn test_init_valid() {
        let config = default_config();
        let mut module = PtraceMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = default_config();
        config.scan_interval_secs = 0;
        let mut module = PtraceMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let mut config = default_config();
        config.scan_interval_secs = 3600;
        let mut module = PtraceMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();
        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = default_config();
        let module = PtraceMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // 最低でも現在のプロセスがスキャン対象に含まれるはず
        assert!(result.items_scanned > 0);
    }

    // --- PtraceFinding tests ---

    #[test]
    fn test_publish_findings_no_bus() {
        let findings = vec![PtraceFinding {
            pid: 1234,
            process_name: "target".to_string(),
            tracer_pid: 5678,
            tracer_name: "attacker".to_string(),
        }];
        // event_bus が None でもパニックしない
        PtraceMonitorModule::publish_findings(&findings, &None);
    }

    #[test]
    fn test_publish_findings_empty() {
        let findings: Vec<PtraceFinding> = Vec::new();
        PtraceMonitorModule::publish_findings(&findings, &None);
    }
}
