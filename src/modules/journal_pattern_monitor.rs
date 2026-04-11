//! systemd ジャーナルパターン監視モジュール
//!
//! `journalctl` コマンドでジャーナルログを定期取得し、設定されたパターン（正規表現）と
//! マッチングしてセキュリティイベントを発行する。
//!
//! 検知対象:
//! - 認証失敗（ブルートフォース等）
//! - 権限昇格操作
//! - サービスクラッシュ（segfault / core dump）
//! - カーネル警告
//! - OOM Killer 発動

use crate::config::{JournalPattern, JournalPatternMonitorConfig};
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use regex::Regex;
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

/// コンパイル済みパターン
#[derive(Debug, Clone)]
struct CompiledPattern {
    /// パターン名
    name: String,
    /// コンパイル済み正規表現
    regex: Regex,
    /// 重要度
    severity: Severity,
    /// ユニットフィルター
    unit_filter: Option<String>,
}

/// デフォルトプリセットパターンを返す
fn preset_patterns() -> Vec<JournalPattern> {
    vec![
        JournalPattern {
            name: "auth_failure".to_string(),
            pattern: r"(?i)(authentication failure|Failed password|Invalid user|pam_unix.*authentication failure)".to_string(),
            severity: "warning".to_string(),
            unit_filter: None,
        },
        JournalPattern {
            name: "privilege_escalation".to_string(),
            pattern: r"(?i)(sudo:.*COMMAND|su:.*session opened|pkexec.*executing)".to_string(),
            severity: "warning".to_string(),
            unit_filter: None,
        },
        JournalPattern {
            name: "service_crash".to_string(),
            pattern: r"(?i)(segfault|core dumped|dumped core|fatal signal)".to_string(),
            severity: "warning".to_string(),
            unit_filter: None,
        },
        JournalPattern {
            name: "kernel_warning".to_string(),
            pattern: r"(?i)(kernel:.*WARNING|kernel:.*BUG|kernel:.*Oops)".to_string(),
            severity: "warning".to_string(),
            unit_filter: None,
        },
        JournalPattern {
            name: "oom_killer".to_string(),
            pattern: r"(?i)(Out of memory|oom-kill|invoked oom-killer|Killed process)".to_string(),
            severity: "critical".to_string(),
            unit_filter: None,
        },
    ]
}

/// パターンリストをコンパイルする
fn compile_patterns(patterns: &[JournalPattern]) -> Result<Vec<CompiledPattern>, AppError> {
    let mut compiled = Vec::with_capacity(patterns.len());
    for p in patterns {
        let regex = Regex::new(&p.pattern).map_err(|e| AppError::ModuleConfig {
            message: format!(
                "ジャーナルパターン '{}' の正規表現が不正です: {}",
                p.name, e
            ),
        })?;
        let severity = Severity::parse(&p.severity).unwrap_or(Severity::Warning);
        compiled.push(CompiledPattern {
            name: p.name.clone(),
            regex,
            severity,
            unit_filter: p.unit_filter.clone(),
        });
    }
    Ok(compiled)
}

/// 有効なパターンリストを構築する（プリセット + カスタム）
fn build_pattern_list(config: &JournalPatternMonitorConfig) -> Vec<JournalPattern> {
    let mut patterns = Vec::new();
    if config.use_preset_patterns {
        patterns.extend(preset_patterns());
    }
    patterns.extend(config.custom_patterns.clone());
    patterns
}

/// journalctl の JSON 出力行から MESSAGE フィールドを抽出する
fn extract_message(line: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    value
        .get("MESSAGE")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// journalctl の JSON 出力行から _SYSTEMD_UNIT フィールドを抽出する
fn extract_unit(line: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    value
        .get("_SYSTEMD_UNIT")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// ジャーナルエントリをパターンとマッチングし、マッチしたパターン情報を返す
fn match_entry(
    message: &str,
    unit: Option<&str>,
    patterns: &[CompiledPattern],
) -> Vec<(String, Severity)> {
    let mut matches = Vec::new();
    for p in patterns {
        if let Some(ref filter) = p.unit_filter {
            if let Some(u) = unit {
                if u != filter {
                    continue;
                }
            } else {
                continue;
            }
        }
        if p.regex.is_match(message) {
            matches.push((p.name.clone(), p.severity.clone()));
        }
    }
    matches
}

/// journalctl を実行してエントリを取得する
async fn run_journalctl(
    journalctl_path: &str,
    since: &str,
    max_entries: usize,
) -> Result<Vec<String>, AppError> {
    let output = tokio::process::Command::new(journalctl_path)
        .args(["--since", since, "--no-pager", "-o", "json"])
        .output()
        .await
        .map_err(|e| AppError::ModuleConfig {
            message: format!("journalctl の実行に失敗しました: {}", e),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(
            exit_code = ?output.status.code(),
            stderr = %stderr,
            "journalctl がエラーで終了しました"
        );
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<String> = stdout
        .lines()
        .take(max_entries)
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect();

    Ok(lines)
}

/// systemd ジャーナルパターン監視モジュール
///
/// journalctl でジャーナルログを定期取得し、設定されたパターンとマッチングして
/// セキュリティイベントを発行する。
pub struct JournalPatternMonitorModule {
    config: JournalPatternMonitorConfig,
    event_bus: Option<EventBus>,
    cancel_token: CancellationToken,
}

impl JournalPatternMonitorModule {
    /// 新しい systemd ジャーナルパターン監視モジュールを作成する
    pub fn new(config: JournalPatternMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            event_bus,
            cancel_token: CancellationToken::new(),
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }
}

impl Module for JournalPatternMonitorModule {
    fn name(&self) -> &str {
        "journal_pattern_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.max_entries_per_scan == 0 {
            return Err(AppError::ModuleConfig {
                message: "max_entries_per_scan は 0 より大きい値を指定してください".to_string(),
            });
        }

        let path = std::path::Path::new(&self.config.journalctl_path);
        if !path.exists() {
            tracing::warn!(
                path = %self.config.journalctl_path,
                "journalctl が見つかりません — モジュールは動作しますが、ログ取得に失敗する可能性があります"
            );
        }

        let patterns = build_pattern_list(&self.config);
        compile_patterns(&patterns)?;

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            max_entries_per_scan = self.config.max_entries_per_scan,
            pattern_count = patterns.len(),
            "systemd ジャーナルパターン監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let patterns = build_pattern_list(&self.config);
        let compiled = compile_patterns(&patterns)?;

        let scan_interval_secs = self.config.scan_interval_secs;
        let max_entries = self.config.max_entries_per_scan;
        let journalctl_path = self.config.journalctl_path.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("systemd ジャーナルパターン監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let since = format!("{} seconds ago", scan_interval_secs);

                        let lines = match run_journalctl(&journalctl_path, &since, max_entries).await {
                            Ok(l) => l,
                            Err(e) => {
                                tracing::warn!(error = %e, "ジャーナルログの取得に失敗しました");
                                continue;
                            }
                        };

                        let mut total_matches = 0usize;

                        for line in &lines {
                            let message = match extract_message(line) {
                                Some(m) => m,
                                None => continue,
                            };
                            let unit = extract_unit(line);

                            let hits = match_entry(&message, unit.as_deref(), &compiled);
                            for (pattern_name, severity) in &hits {
                                total_matches += 1;
                                tracing::warn!(
                                    pattern = %pattern_name,
                                    message = %message,
                                    "ジャーナルパターンが検知されました"
                                );
                                if let Some(ref bus) = event_bus {
                                    let truncated = if message.len() > 200 {
                                        let end = message
                                            .char_indices()
                                            .map(|(i, _)| i)
                                            .take_while(|&i| i <= 200)
                                            .last()
                                            .unwrap_or(0);
                                        format!("{}…", &message[..end])
                                    } else {
                                        message.clone()
                                    };
                                    bus.publish(
                                        SecurityEvent::new(
                                            format!("journal_pattern_{}", pattern_name),
                                            severity.clone(),
                                            "journal_pattern_monitor",
                                            format!(
                                                "ジャーナルパターン '{}' が検知されました: {}",
                                                pattern_name, truncated
                                            ),
                                        )
                                        .with_details(format!(
                                            "pattern={}, unit={}",
                                            pattern_name,
                                            unit.as_deref().unwrap_or("N/A")
                                        )),
                                    );
                                }
                            }
                        }

                        if total_matches == 0 {
                            tracing::debug!(
                                entries = lines.len(),
                                "ジャーナルパターンの検知はありません"
                            );
                        } else {
                            tracing::info!(
                                entries = lines.len(),
                                matches = total_matches,
                                "ジャーナルパターンスキャン完了"
                            );
                        }

                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let patterns = build_pattern_list(&self.config);
        let compiled = compile_patterns(&patterns)?;

        let lines = run_journalctl(
            &self.config.journalctl_path,
            "5 minutes ago",
            self.config.max_entries_per_scan,
        )
        .await?;

        let mut issues_found = 0usize;
        let mut snapshot = BTreeMap::new();

        for line in &lines {
            let message = match extract_message(line) {
                Some(m) => m,
                None => continue,
            };
            let unit = extract_unit(line);
            let hits = match_entry(&message, unit.as_deref(), &compiled);
            issues_found += hits.len();
        }

        for p in &patterns {
            snapshot.insert(
                format!("pattern:{}", p.name),
                format!("severity={}", p.severity),
            );
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned: lines.len(),
            issues_found,
            duration,
            summary: format!(
                "直近5分のジャーナルログ {}件をスキャンし、パターンマッチ {}件を検知しました",
                lines.len(),
                issues_found
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

    fn default_config() -> JournalPatternMonitorConfig {
        JournalPatternMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            max_entries_per_scan: 1000,
            journalctl_path: "/usr/bin/journalctl".to_string(),
            use_preset_patterns: true,
            custom_patterns: vec![],
        }
    }

    #[test]
    fn test_preset_patterns_count() {
        let presets = preset_patterns();
        assert_eq!(presets.len(), 5);
    }

    #[test]
    fn test_preset_patterns_compile() {
        let presets = preset_patterns();
        let result = compile_patterns(&presets);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 5);
    }

    #[test]
    fn test_compile_invalid_pattern() {
        let patterns = vec![JournalPattern {
            name: "bad".to_string(),
            pattern: "[invalid".to_string(),
            severity: "warning".to_string(),
            unit_filter: None,
        }];
        let result = compile_patterns(&patterns);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_message_valid() {
        let json = r#"{"MESSAGE": "Failed password for root", "_SYSTEMD_UNIT": "sshd.service"}"#;
        let msg = extract_message(json);
        assert_eq!(msg, Some("Failed password for root".to_string()));
    }

    #[test]
    fn test_extract_message_missing() {
        let json = r#"{"OTHER_FIELD": "value"}"#;
        let msg = extract_message(json);
        assert!(msg.is_none());
    }

    #[test]
    fn test_extract_message_invalid_json() {
        let msg = extract_message("not json");
        assert!(msg.is_none());
    }

    #[test]
    fn test_extract_unit() {
        let json = r#"{"MESSAGE": "test", "_SYSTEMD_UNIT": "sshd.service"}"#;
        let unit = extract_unit(json);
        assert_eq!(unit, Some("sshd.service".to_string()));
    }

    #[test]
    fn test_extract_unit_missing() {
        let json = r#"{"MESSAGE": "test"}"#;
        let unit = extract_unit(json);
        assert!(unit.is_none());
    }

    #[test]
    fn test_match_entry_auth_failure() {
        let presets = preset_patterns();
        let compiled = compile_patterns(&presets).unwrap();
        let matches = match_entry("Failed password for root from 192.168.1.1", None, &compiled);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "auth_failure");
    }

    #[test]
    fn test_match_entry_privilege_escalation() {
        let presets = preset_patterns();
        let compiled = compile_patterns(&presets).unwrap();
        let matches = match_entry("sudo: user : COMMAND=/usr/bin/ls", None, &compiled);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "privilege_escalation");
    }

    #[test]
    fn test_match_entry_service_crash() {
        let presets = preset_patterns();
        let compiled = compile_patterns(&presets).unwrap();
        let matches = match_entry("myapp[1234]: segfault at 0000000000000000", None, &compiled);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "service_crash");
    }

    #[test]
    fn test_match_entry_kernel_warning() {
        let presets = preset_patterns();
        let compiled = compile_patterns(&presets).unwrap();
        let matches = match_entry("kernel: WARNING: CPU: 0 PID: 1", None, &compiled);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "kernel_warning");
    }

    #[test]
    fn test_match_entry_oom_killer() {
        let presets = preset_patterns();
        let compiled = compile_patterns(&presets).unwrap();
        let matches = match_entry("Out of memory: Killed process 1234", None, &compiled);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "oom_killer");
    }

    #[test]
    fn test_match_entry_no_match() {
        let presets = preset_patterns();
        let compiled = compile_patterns(&presets).unwrap();
        let matches = match_entry("systemd[1]: Started foo.service.", None, &compiled);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_entry_unit_filter_match() {
        let patterns = vec![JournalPattern {
            name: "sshd_auth".to_string(),
            pattern: "Failed password".to_string(),
            severity: "warning".to_string(),
            unit_filter: Some("sshd.service".to_string()),
        }];
        let compiled = compile_patterns(&patterns).unwrap();
        let matches = match_entry("Failed password for root", Some("sshd.service"), &compiled);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_entry_unit_filter_no_match() {
        let patterns = vec![JournalPattern {
            name: "sshd_auth".to_string(),
            pattern: "Failed password".to_string(),
            severity: "warning".to_string(),
            unit_filter: Some("sshd.service".to_string()),
        }];
        let compiled = compile_patterns(&patterns).unwrap();
        let matches = match_entry("Failed password for root", Some("other.service"), &compiled);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_entry_unit_filter_no_unit() {
        let patterns = vec![JournalPattern {
            name: "sshd_auth".to_string(),
            pattern: "Failed password".to_string(),
            severity: "warning".to_string(),
            unit_filter: Some("sshd.service".to_string()),
        }];
        let compiled = compile_patterns(&patterns).unwrap();
        let matches = match_entry("Failed password for root", None, &compiled);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_build_pattern_list_preset_only() {
        let config = default_config();
        let patterns = build_pattern_list(&config);
        assert_eq!(patterns.len(), 5);
    }

    #[test]
    fn test_build_pattern_list_no_preset() {
        let mut config = default_config();
        config.use_preset_patterns = false;
        config.custom_patterns = vec![JournalPattern {
            name: "custom".to_string(),
            pattern: "test".to_string(),
            severity: "info".to_string(),
            unit_filter: None,
        }];
        let patterns = build_pattern_list(&config);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].name, "custom");
    }

    #[test]
    fn test_build_pattern_list_preset_and_custom() {
        let mut config = default_config();
        config.custom_patterns = vec![JournalPattern {
            name: "custom".to_string(),
            pattern: "test".to_string(),
            severity: "info".to_string(),
            unit_filter: None,
        }];
        let patterns = build_pattern_list(&config);
        assert_eq!(patterns.len(), 6);
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = default_config();
        config.scan_interval_secs = 0;
        let mut module = JournalPatternMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_zero_max_entries() {
        let mut config = default_config();
        config.max_entries_per_scan = 0;
        let mut module = JournalPatternMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid_config() {
        let config = default_config();
        let mut module = JournalPatternMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_invalid_pattern() {
        let mut config = default_config();
        config.use_preset_patterns = false;
        config.custom_patterns = vec![JournalPattern {
            name: "bad".to_string(),
            pattern: "[invalid".to_string(),
            severity: "warning".to_string(),
            unit_filter: None,
        }];
        let mut module = JournalPatternMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_severity_mapping() {
        let patterns = vec![
            JournalPattern {
                name: "info_test".to_string(),
                pattern: "test".to_string(),
                severity: "info".to_string(),
                unit_filter: None,
            },
            JournalPattern {
                name: "warning_test".to_string(),
                pattern: "test".to_string(),
                severity: "warning".to_string(),
                unit_filter: None,
            },
            JournalPattern {
                name: "critical_test".to_string(),
                pattern: "test".to_string(),
                severity: "critical".to_string(),
                unit_filter: None,
            },
            JournalPattern {
                name: "unknown_test".to_string(),
                pattern: "test".to_string(),
                severity: "unknown".to_string(),
                unit_filter: None,
            },
        ];
        let compiled = compile_patterns(&patterns).unwrap();
        assert_eq!(compiled[0].severity, Severity::Info);
        assert_eq!(compiled[1].severity, Severity::Warning);
        assert_eq!(compiled[2].severity, Severity::Critical);
        assert_eq!(compiled[3].severity, Severity::Warning);
    }

    #[test]
    fn test_multiple_pattern_matches() {
        let presets = preset_patterns();
        let compiled = compile_patterns(&presets).unwrap();
        let matches = match_entry(
            "Out of memory: Killed process 1234 (segfault)",
            None,
            &compiled,
        );
        assert!(matches.len() >= 2);
    }

    #[test]
    fn test_case_insensitive_matching() {
        let presets = preset_patterns();
        let compiled = compile_patterns(&presets).unwrap();

        let matches1 = match_entry("FAILED PASSWORD for root", None, &compiled);
        assert!(!matches1.is_empty());

        let matches2 = match_entry("failed password for root", None, &compiled);
        assert!(!matches2.is_empty());
    }
}
