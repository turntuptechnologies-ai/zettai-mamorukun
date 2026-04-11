//! auditd ログ統合モジュール
//!
//! Linux Audit サブシステム（auditd）のログファイルを定期的に読み取り、
//! セキュリティ関連のイベントを検知してアラートを発行する。
//!
//! 検知対象:
//! - EXECVE — コマンド実行イベント
//! - SYSCALL — 権限昇格系システムコール（setuid, setgid, ptrace 等）
//! - USER_AUTH / USER_LOGIN — 認証・ログインイベント
//! - AVC — SELinux 拒否イベント
//! - ANOMALY — カーネル異常検知

use crate::config::AuditdMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// auditd ログの1行を解析した結果
struct AuditdLogEntry {
    /// イベントタイプ（EXECVE, SYSCALL, USER_AUTH 等）
    event_type: String,
    /// タイムスタンプ文字列
    timestamp: String,
    /// メッセージ ID
    message_id: String,
    /// メッセージ本体
    body: String,
}

/// auditd ログのスキャン結果
#[allow(dead_code)]
struct AuditScanResult {
    /// 新しいファイルオフセット
    new_offset: u64,
    /// スキャンしたエントリ数
    items_scanned: usize,
    /// 検知されたイベント数
    issues_found: usize,
    /// スナップショットデータ
    snapshot: BTreeMap<String, String>,
}

/// auditd ログ統合モジュール
pub struct AuditdMonitorModule {
    config: AuditdMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl AuditdMonitorModule {
    /// 新しい auditd ログ統合モジュールを作成する
    pub fn new(config: AuditdMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// auditd ログの1行を解析する
    ///
    /// フォーマット: `type=TYPE msg=audit(TIMESTAMP:ID): BODY`
    fn parse_audit_line(line: &str) -> Option<AuditdLogEntry> {
        // type= を探す
        let type_start = line.find("type=")?;
        let after_type = &line[type_start + 5..];
        let type_end = after_type.find(' ').unwrap_or(after_type.len());
        let event_type = after_type[..type_end].to_string();

        if event_type.is_empty() {
            return None;
        }

        // msg=audit( を探す
        let msg_marker = "msg=audit(";
        let msg_start = line.find(msg_marker)?;
        let after_msg = &line[msg_start + msg_marker.len()..];

        // タイムスタンプ:ID を抽出
        let close_paren = after_msg.find(')')?;
        let ts_id = &after_msg[..close_paren];
        let colon_pos = ts_id.find(':')?;
        let timestamp = ts_id[..colon_pos].to_string();
        let message_id = ts_id[colon_pos + 1..].to_string();

        // ): の後がボディ
        let body_start = msg_start + msg_marker.len() + close_paren + 1;
        let body = if body_start < line.len() {
            line[body_start..].trim_start_matches(": ").to_string()
        } else {
            String::new()
        };

        Some(AuditdLogEntry {
            event_type,
            timestamp,
            message_id,
            body,
        })
    }

    /// エントリの種別に基づいて Severity, event_type 名, メッセージを返す
    fn classify_event(entry: &AuditdLogEntry) -> (Severity, &str, String) {
        if entry.event_type == "AVC" {
            return (
                Severity::Warning,
                "auditd_avc_denied",
                format!("SELinux AVC 拒否イベントを検知しました: {}", entry.body),
            );
        }

        if entry.event_type.starts_with("ANOMALY") {
            return (
                Severity::Critical,
                "auditd_anomaly",
                format!(
                    "カーネル異常イベントを検知しました: {} — {}",
                    entry.event_type, entry.body
                ),
            );
        }

        if entry.event_type == "SYSCALL" {
            let has_success = entry.body.contains("success=yes");
            let has_priv_syscall = entry.body.contains("setuid")
                || entry.body.contains("setgid")
                || entry.body.contains("ptrace")
                || entry.body.contains("setresuid")
                || entry.body.contains("setresgid");
            if has_success && has_priv_syscall {
                return (
                    Severity::Warning,
                    "auditd_privilege_escalation",
                    format!("権限昇格系システムコールを検知しました: {}", entry.body),
                );
            }
        }

        if entry.event_type == "USER_AUTH" || entry.event_type == "USER_LOGIN" {
            if entry.body.contains("res=failed") {
                return (
                    Severity::Warning,
                    "auditd_auth_failure",
                    format!(
                        "認証失敗を検知しました: {} — {}",
                        entry.event_type, entry.body
                    ),
                );
            }
            if entry.body.contains("res=success") {
                return (
                    Severity::Info,
                    "auditd_auth_success",
                    format!(
                        "認証成功を記録しました: {} — {}",
                        entry.event_type, entry.body
                    ),
                );
            }
        }

        if entry.event_type == "EXECVE" {
            return (
                Severity::Info,
                "auditd_exec",
                format!("コマンド実行を記録しました: {}", entry.body),
            );
        }

        (
            Severity::Info,
            "auditd_event",
            format!(
                "auditd イベントを記録しました: {} — {}",
                entry.event_type, entry.body
            ),
        )
    }

    /// auditd ログファイルを差分読み取りし、新しいエントリを処理する
    fn scan_audit_log(
        log_path: &Path,
        last_offset: u64,
        watch_types: &[String],
        event_bus: &Option<EventBus>,
    ) -> AuditScanResult {
        let metadata = match std::fs::metadata(log_path) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(
                    path = %log_path.display(),
                    error = %e,
                    "auditd ログファイルのメタデータ取得に失敗しました"
                );
                return AuditScanResult {
                    new_offset: last_offset,
                    items_scanned: 0,
                    issues_found: 0,
                    snapshot: BTreeMap::new(),
                };
            }
        };

        let file_size = metadata.len();

        // ログローテーション検知: ファイルサイズが縮小した場合はオフセットをリセット
        let effective_offset = if file_size < last_offset {
            tracing::info!(
                path = %log_path.display(),
                old_offset = last_offset,
                new_size = file_size,
                "ログローテーションを検知しました。オフセットをリセットします"
            );
            0
        } else {
            last_offset
        };

        if file_size == effective_offset {
            return AuditScanResult {
                new_offset: file_size,
                items_scanned: 0,
                issues_found: 0,
                snapshot: BTreeMap::new(),
            };
        }

        let content = match std::fs::read_to_string(log_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(
                    path = %log_path.display(),
                    error = %e,
                    "auditd ログファイルの読み取りに失敗しました"
                );
                return AuditScanResult {
                    new_offset: last_offset,
                    items_scanned: 0,
                    issues_found: 0,
                    snapshot: BTreeMap::new(),
                };
            }
        };

        let mut items_scanned: usize = 0;
        let mut issues_found: usize = 0;
        let mut snapshot = BTreeMap::new();

        // effective_offset 以降のバイトを処理
        let bytes = content.as_bytes();
        let start = effective_offset as usize;
        if start < bytes.len() {
            let tail = String::from_utf8_lossy(&bytes[start..]);
            for line in tail.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                if let Some(entry) = Self::parse_audit_line(trimmed) {
                    if !watch_types.iter().any(|t| t == &entry.event_type) {
                        continue;
                    }

                    items_scanned += 1;
                    let (severity, event_type_name, message) = Self::classify_event(&entry);

                    let key = format!(
                        "{}:{}:{}",
                        entry.event_type, entry.timestamp, entry.message_id
                    );
                    snapshot.insert(key, format!("{}:{}", event_type_name, entry.event_type));

                    if severity >= Severity::Warning {
                        issues_found += 1;
                    }

                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                event_type_name,
                                severity,
                                "auditd_monitor",
                                message,
                            )
                            .with_details(format!(
                                "type={} timestamp={} id={}",
                                entry.event_type, entry.timestamp, entry.message_id
                            )),
                        );
                    }
                }
            }
        }

        AuditScanResult {
            new_offset: file_size,
            items_scanned,
            issues_found,
            snapshot,
        }
    }
}

impl Module for AuditdMonitorModule {
    fn name(&self) -> &str {
        "auditd_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.check_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "check_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if !self.config.log_path.exists() {
            tracing::warn!(
                path = %self.config.log_path.display(),
                "auditd ログファイルが存在しません"
            );
        }

        tracing::info!(
            log_path = %self.config.log_path.display(),
            check_interval_secs = self.config.check_interval_secs,
            watch_types = ?self.config.watch_types,
            "auditd ログ統合モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let log_path = self.config.log_path.clone();
        let check_interval_secs = self.config.check_interval_secs;
        let watch_types = self.config.watch_types.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 初回スキャン — 現在のファイル末尾からオフセットを設定
        let initial_result = Self::scan_audit_log(&log_path, 0, &watch_types, &event_bus);
        let offset =
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(initial_result.new_offset));
        tracing::info!(
            items_scanned = initial_result.items_scanned,
            issues_found = initial_result.issues_found,
            offset = initial_result.new_offset,
            "auditd ログの初回スキャンが完了しました"
        );

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(check_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("auditd ログ統合モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current_offset = offset.load(std::sync::atomic::Ordering::Relaxed);
                        let result = AuditdMonitorModule::scan_audit_log(
                            &log_path,
                            current_offset,
                            &watch_types,
                            &event_bus,
                        );
                        offset.store(result.new_offset, std::sync::atomic::Ordering::Relaxed);
                        tracing::debug!(
                            items_scanned = result.items_scanned,
                            issues_found = result.issues_found,
                            offset = result.new_offset,
                            "auditd ログの定期スキャンが完了しました"
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

        // ログファイルの末尾100行を読み取ってスナップショットを作成
        let mut snapshot = BTreeMap::new();
        let mut items_scanned: usize = 0;
        let mut issues_found: usize = 0;

        if self.config.log_path.exists() {
            match std::fs::read_to_string(&self.config.log_path) {
                Ok(content) => {
                    let lines: Vec<&str> = content.lines().collect();
                    let start_idx = if lines.len() > 100 {
                        lines.len() - 100
                    } else {
                        0
                    };
                    for line in &lines[start_idx..] {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        if let Some(entry) = Self::parse_audit_line(trimmed) {
                            if !self
                                .config
                                .watch_types
                                .iter()
                                .any(|t| t == &entry.event_type)
                            {
                                continue;
                            }
                            items_scanned += 1;
                            let (severity, event_type_name, _) = Self::classify_event(&entry);
                            let key = format!(
                                "{}:{}:{}",
                                entry.event_type, entry.timestamp, entry.message_id
                            );
                            snapshot
                                .insert(key, format!("{}:{}", event_type_name, entry.event_type));
                            if severity >= Severity::Warning {
                                issues_found += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        path = %self.config.log_path.display(),
                        error = %e,
                        "auditd ログファイルの読み取りに失敗しました"
                    );
                }
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "auditd ログ {}件をスキャンしました（問題: {}件）",
                items_scanned, issues_found,
            ),
            snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_audit_line_execve() {
        let line = "type=EXECVE msg=audit(1680000000.123:456): argc=3 a0=\"/usr/bin/ls\" a1=\"-la\" a2=\"/tmp\"";
        let entry = AuditdMonitorModule::parse_audit_line(line).unwrap();
        assert_eq!(entry.event_type, "EXECVE");
        assert_eq!(entry.timestamp, "1680000000.123");
        assert_eq!(entry.message_id, "456");
        assert!(entry.body.contains("argc=3"));
    }

    #[test]
    fn test_parse_audit_line_syscall() {
        let line = "type=SYSCALL msg=audit(1680000001.000:789): arch=c000003e syscall=105 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=0 ppid=1 pid=1234 comm=\"sudo\" exe=\"/usr/bin/sudo\" key=\"setuid\"";
        let entry = AuditdMonitorModule::parse_audit_line(line).unwrap();
        assert_eq!(entry.event_type, "SYSCALL");
        assert_eq!(entry.timestamp, "1680000001.000");
        assert_eq!(entry.message_id, "789");
        assert!(entry.body.contains("success=yes"));
    }

    #[test]
    fn test_parse_audit_line_user_auth() {
        let line = "type=USER_AUTH msg=audit(1680000002.500:100): pid=5678 uid=0 auid=1000 ses=1 msg='op=PAM:authentication acct=\"root\" exe=\"/usr/bin/su\" hostname=? addr=? terminal=/dev/pts/0 res=failed'";
        let entry = AuditdMonitorModule::parse_audit_line(line).unwrap();
        assert_eq!(entry.event_type, "USER_AUTH");
        assert_eq!(entry.timestamp, "1680000002.500");
        assert_eq!(entry.message_id, "100");
    }

    #[test]
    fn test_parse_audit_line_avc() {
        let line = "type=AVC msg=audit(1680000003.000:200): avc:  denied  { read } for  pid=1234 comm=\"httpd\" name=\"secret.txt\" dev=\"sda1\" ino=56789 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0";
        let entry = AuditdMonitorModule::parse_audit_line(line).unwrap();
        assert_eq!(entry.event_type, "AVC");
        assert_eq!(entry.timestamp, "1680000003.000");
        assert_eq!(entry.message_id, "200");
        assert!(entry.body.contains("denied"));
    }

    #[test]
    fn test_parse_audit_line_invalid() {
        // No type= prefix
        assert!(AuditdMonitorModule::parse_audit_line("some random log line").is_none());
        // Missing msg=audit(
        assert!(
            AuditdMonitorModule::parse_audit_line("type=EXECVE no audit marker here").is_none()
        );
        // Empty line
        assert!(AuditdMonitorModule::parse_audit_line("").is_none());
    }

    #[test]
    fn test_classify_event_avc() {
        let entry = AuditdLogEntry {
            event_type: "AVC".to_string(),
            timestamp: "1680000000.000".to_string(),
            message_id: "1".to_string(),
            body: "avc: denied { read }".to_string(),
        };
        let (severity, event_type, _) = AuditdMonitorModule::classify_event(&entry);
        assert_eq!(severity, Severity::Warning);
        assert_eq!(event_type, "auditd_avc_denied");
    }

    #[test]
    fn test_classify_event_anomaly() {
        let entry = AuditdLogEntry {
            event_type: "ANOMALY_ABEND".to_string(),
            timestamp: "1680000000.000".to_string(),
            message_id: "2".to_string(),
            body: "sig=11".to_string(),
        };
        let (severity, event_type, _) = AuditdMonitorModule::classify_event(&entry);
        assert_eq!(severity, Severity::Critical);
        assert_eq!(event_type, "auditd_anomaly");
    }

    #[test]
    fn test_classify_event_privilege_escalation() {
        let entry = AuditdLogEntry {
            event_type: "SYSCALL".to_string(),
            timestamp: "1680000000.000".to_string(),
            message_id: "3".to_string(),
            body: "arch=c000003e syscall=105 success=yes exit=0 comm=\"sudo\" key=\"setuid\""
                .to_string(),
        };
        let (severity, event_type, _) = AuditdMonitorModule::classify_event(&entry);
        assert_eq!(severity, Severity::Warning);
        assert_eq!(event_type, "auditd_privilege_escalation");
    }

    #[test]
    fn test_classify_event_auth_failure() {
        let entry = AuditdLogEntry {
            event_type: "USER_AUTH".to_string(),
            timestamp: "1680000000.000".to_string(),
            message_id: "4".to_string(),
            body: "pid=1234 uid=0 res=failed".to_string(),
        };
        let (severity, event_type, _) = AuditdMonitorModule::classify_event(&entry);
        assert_eq!(severity, Severity::Warning);
        assert_eq!(event_type, "auditd_auth_failure");
    }

    #[test]
    fn test_classify_event_auth_success() {
        let entry = AuditdLogEntry {
            event_type: "USER_AUTH".to_string(),
            timestamp: "1680000000.000".to_string(),
            message_id: "5".to_string(),
            body: "pid=1234 uid=0 res=success".to_string(),
        };
        let (severity, event_type, _) = AuditdMonitorModule::classify_event(&entry);
        assert_eq!(severity, Severity::Info);
        assert_eq!(event_type, "auditd_auth_success");
    }

    #[test]
    fn test_classify_event_execve() {
        let entry = AuditdLogEntry {
            event_type: "EXECVE".to_string(),
            timestamp: "1680000000.000".to_string(),
            message_id: "6".to_string(),
            body: "argc=1 a0=\"/usr/bin/ls\"".to_string(),
        };
        let (severity, event_type, _) = AuditdMonitorModule::classify_event(&entry);
        assert_eq!(severity, Severity::Info);
        assert_eq!(event_type, "auditd_exec");
    }

    #[test]
    fn test_scan_nonexistent_log() {
        let result = AuditdMonitorModule::scan_audit_log(
            Path::new("/tmp/nonexistent-auditd-test-12345.log"),
            0,
            &["EXECVE".to_string()],
            &None,
        );
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
        assert_eq!(result.new_offset, 0);
    }

    #[test]
    fn test_scan_empty_log() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let log_path = tmpdir.path().join("audit.log");
        std::fs::write(&log_path, "").unwrap();

        let result =
            AuditdMonitorModule::scan_audit_log(&log_path, 0, &["EXECVE".to_string()], &None);
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
        assert_eq!(result.new_offset, 0);
    }

    #[test]
    fn test_scan_with_entries() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let log_path = tmpdir.path().join("audit.log");
        let content = "\
type=EXECVE msg=audit(1680000000.123:1): argc=1 a0=\"/usr/bin/ls\"
type=AVC msg=audit(1680000001.000:2): avc: denied { read } for pid=1234
type=SYSCALL msg=audit(1680000002.000:3): arch=c000003e syscall=105 success=yes key=\"setuid\"
";
        std::fs::write(&log_path, content).unwrap();

        let watch_types = vec![
            "EXECVE".to_string(),
            "AVC".to_string(),
            "SYSCALL".to_string(),
        ];
        let result = AuditdMonitorModule::scan_audit_log(&log_path, 0, &watch_types, &None);

        assert_eq!(result.items_scanned, 3);
        // AVC (High) + SYSCALL with setuid (Warning) = 2 issues
        assert_eq!(result.issues_found, 2);
        assert_eq!(result.snapshot.len(), 3);
        assert_eq!(result.new_offset, content.len() as u64);
    }

    #[test]
    fn test_scan_log_rotation() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let log_path = tmpdir.path().join("audit.log");

        // ファイルサイズより大きいオフセットを設定（ローテーション後のシナリオ）
        let content = "type=EXECVE msg=audit(1680000000.123:1): argc=1 a0=\"/usr/bin/ls\"\n";
        std::fs::write(&log_path, content).unwrap();

        let large_offset = 999999;
        let watch_types = vec!["EXECVE".to_string()];
        let result =
            AuditdMonitorModule::scan_audit_log(&log_path, large_offset, &watch_types, &None);

        // オフセットがリセットされ、ファイル全体が読み取られるはず
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.new_offset, content.len() as u64);
    }

    #[test]
    fn test_init_zero_interval() {
        let config = AuditdMonitorConfig {
            enabled: true,
            check_interval_secs: 0,
            log_path: PathBuf::from("/var/log/audit/audit.log"),
            watch_types: vec!["EXECVE".to_string()],
        };
        let mut module = AuditdMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = AuditdMonitorConfig {
            enabled: true,
            check_interval_secs: 30,
            log_path: PathBuf::from("/tmp/nonexistent-auditd-test"),
            watch_types: vec!["EXECVE".to_string()],
        };
        let mut module = AuditdMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_default_config() {
        let config = AuditdMonitorConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.check_interval_secs, 30);
        assert_eq!(config.log_path, PathBuf::from("/var/log/audit/audit.log"));
        assert_eq!(config.watch_types.len(), 6);
        assert!(config.watch_types.contains(&"EXECVE".to_string()));
        assert!(config.watch_types.contains(&"SYSCALL".to_string()));
        assert!(config.watch_types.contains(&"USER_AUTH".to_string()));
        assert!(config.watch_types.contains(&"USER_LOGIN".to_string()));
        assert!(config.watch_types.contains(&"AVC".to_string()));
        assert!(config.watch_types.contains(&"ANOMALY".to_string()));
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let log_path = tmpdir.path().join("audit.log");
        std::fs::write(&log_path, "").unwrap();

        let config = AuditdMonitorConfig {
            enabled: true,
            check_interval_secs: 3600,
            log_path,
            watch_types: vec!["EXECVE".to_string()],
        };
        let mut module = AuditdMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan_no_file() {
        let config = AuditdMonitorConfig {
            enabled: true,
            check_interval_secs: 30,
            log_path: PathBuf::from("/tmp/nonexistent-auditd-initial-scan-test"),
            watch_types: vec!["EXECVE".to_string()],
        };
        let module = AuditdMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
        assert!(result.snapshot.is_empty());
    }
}
