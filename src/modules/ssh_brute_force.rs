//! SSH ブルートフォース検知モジュール
//!
//! `/var/log/auth.log` を監視し、SSH 認証失敗の連続パターンを検知する。
//! IP アドレスごとに認証失敗回数を追跡し、設定された閾値を超えた場合に
//! SecurityEvent を発行する。

use crate::config::SshBruteForceConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::Module;
use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::time::Instant;
use tokio_util::sync::CancellationToken;

/// SSH ブルートフォース検知モジュール
pub struct SshBruteForceModule {
    config: SshBruteForceConfig,
    event_bus: Option<EventBus>,
    cancel_token: CancellationToken,
}

impl SshBruteForceModule {
    /// 新しい SSH ブルートフォース検知モジュールを作成する
    pub fn new(config: SshBruteForceConfig, event_bus: Option<EventBus>) -> Self {
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

    /// ログ行から認証失敗の IP アドレスを抽出する
    fn extract_failed_ip(line: &str, pattern: &Regex) -> Option<String> {
        pattern.captures(line).map(|caps| caps[2].to_string())
    }

    /// 時間窓外の古いエントリを除去する
    fn cleanup_old_entries(
        failure_map: &mut HashMap<String, Vec<Instant>>,
        time_window: std::time::Duration,
    ) {
        let now = Instant::now();
        failure_map.retain(|_, timestamps| {
            timestamps.retain(|t| now.duration_since(*t) <= time_window);
            !timestamps.is_empty()
        });
    }
}

impl Module for SshBruteForceModule {
    fn name(&self) -> &str {
        "ssh_brute_force"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }
        if self.config.max_failures == 0 {
            return Err(AppError::ModuleConfig {
                message: "max_failures は 0 より大きい値を指定してください".to_string(),
            });
        }
        if self.config.time_window_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "time_window_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if !self.config.auth_log_path.exists() {
            tracing::warn!(
                path = %self.config.auth_log_path.display(),
                "認証ログファイルが存在しません。ファイルが作成されるまで監視をスキップします"
            );
        }

        tracing::info!(
            auth_log_path = %self.config.auth_log_path.display(),
            interval_secs = self.config.interval_secs,
            max_failures = self.config.max_failures,
            time_window_secs = self.config.time_window_secs,
            "SSH ブルートフォース検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let auth_log_path = self.config.auth_log_path.clone();
        let interval_secs = self.config.interval_secs;
        let max_failures = self.config.max_failures;
        let time_window_secs = self.config.time_window_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        tokio::spawn(async move {
            // unwrap safety: このパターンは固定文字列リテラルであり、常に有効な正規表現
            let pattern = Regex::new(
                r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            ).unwrap();

            let time_window = std::time::Duration::from_secs(time_window_secs);
            let mut failure_map: HashMap<String, Vec<Instant>> = HashMap::new();
            let mut last_position: u64 = 0;
            let mut last_file_size: u64 = 0;

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("SSH ブルートフォース検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        // 古いエントリのクリーンアップ
                        SshBruteForceModule::cleanup_old_entries(&mut failure_map, time_window);

                        // ファイルを開く
                        let file = match std::fs::File::open(&auth_log_path) {
                            Ok(f) => f,
                            Err(e) => {
                                tracing::debug!(
                                    path = %auth_log_path.display(),
                                    error = %e,
                                    "認証ログファイルを開けません"
                                );
                                continue;
                            }
                        };

                        // ファイルサイズを確認（truncate/rotate 検知）
                        let metadata = match file.metadata() {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::debug!(error = %e, "メタデータ取得に失敗");
                                continue;
                            }
                        };
                        let current_size = metadata.len();

                        if current_size < last_file_size {
                            // ファイルが truncate/rotate されたので先頭から読み直す
                            tracing::info!("認証ログファイルのローテーションを検知しました。先頭から読み直します");
                            last_position = 0;
                        }
                        last_file_size = current_size;

                        if last_position >= current_size {
                            continue;
                        }

                        // 前回の位置から読み取り
                        let mut reader = BufReader::new(&file);
                        if let Err(e) = reader.seek(SeekFrom::Start(last_position)) {
                            tracing::debug!(error = %e, "seek に失敗");
                            continue;
                        }

                        let mut new_position = last_position;
                        let mut line = String::new();

                        loop {
                            line.clear();
                            match reader.read_line(&mut line) {
                                Ok(0) => break, // EOF
                                Ok(n) => {
                                    new_position += n as u64;
                                    if let Some(ip) = SshBruteForceModule::extract_failed_ip(&line, &pattern) {
                                        let now = Instant::now();
                                        let timestamps = failure_map.entry(ip.clone()).or_default();
                                        timestamps.push(now);

                                        // 時間窓内の失敗回数をチェック
                                        let recent_count = timestamps
                                            .iter()
                                            .filter(|t| now.duration_since(**t) <= time_window)
                                            .count();

                                        if recent_count >= max_failures as usize {
                                            tracing::warn!(
                                                ip = %ip,
                                                failure_count = recent_count,
                                                time_window_secs = time_window_secs,
                                                "SSH ブルートフォース攻撃の可能性を検知しました"
                                            );
                                            if let Some(ref bus) = event_bus {
                                                bus.publish(
                                                    SecurityEvent::new(
                                                        "ssh_brute_force",
                                                        Severity::Critical,
                                                        "ssh_brute_force",
                                                        format!(
                                                            "SSH ブルートフォース攻撃の可能性: IP {} から {}秒以内に {}回の認証失敗",
                                                            ip, time_window_secs, recent_count
                                                        ),
                                                    )
                                                    .with_details(format!("ip={}, failures={}", ip, recent_count)),
                                                );
                                            }
                                            // 重複イベント抑制: 該当 IP のエントリをクリア
                                            failure_map.remove(&ip);
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "行の読み取りに失敗");
                                    break;
                                }
                            }
                        }

                        last_position = new_position;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_config() -> SshBruteForceConfig {
        SshBruteForceConfig {
            enabled: true,
            interval_secs: 30,
            auth_log_path: PathBuf::from("/var/log/auth.log"),
            max_failures: 5,
            time_window_secs: 300,
        }
    }

    fn test_pattern() -> Regex {
        Regex::new(
            r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        ).unwrap()
    }

    #[test]
    fn test_extract_failed_ip_valid() {
        let pattern = test_pattern();
        let line = "Mar 31 10:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2";
        let result = SshBruteForceModule::extract_failed_ip(line, &pattern);
        assert_eq!(result, Some("192.168.1.100".to_string()));
    }

    #[test]
    fn test_extract_failed_ip_invalid_user() {
        let pattern = test_pattern();
        let line = "Mar 31 10:00:00 server sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2";
        let result = SshBruteForceModule::extract_failed_ip(line, &pattern);
        assert_eq!(result, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_extract_failed_ip_no_match() {
        let pattern = test_pattern();
        let line = "Mar 31 10:00:00 server sshd[1234]: Accepted password for root from 192.168.1.100 port 22 ssh2";
        let result = SshBruteForceModule::extract_failed_ip(line, &pattern);
        assert_eq!(result, None);
    }

    #[test]
    fn test_cleanup_old_entries() {
        let mut failure_map: HashMap<String, Vec<Instant>> = HashMap::new();
        let now = Instant::now();
        // 古いエントリ（時間窓外）をシミュレート
        failure_map.insert(
            "192.168.1.1".to_string(),
            vec![now - Duration::from_secs(600)],
        );
        // 新しいエントリ（時間窓内）
        failure_map.insert("192.168.1.2".to_string(), vec![now]);

        let time_window = Duration::from_secs(300);
        SshBruteForceModule::cleanup_old_entries(&mut failure_map, time_window);

        assert!(!failure_map.contains_key("192.168.1.1"));
        assert!(failure_map.contains_key("192.168.1.2"));
    }

    #[test]
    fn test_cleanup_old_entries_empty() {
        let mut failure_map: HashMap<String, Vec<Instant>> = HashMap::new();
        let time_window = Duration::from_secs(300);
        SshBruteForceModule::cleanup_old_entries(&mut failure_map, time_window);
        assert!(failure_map.is_empty());
    }

    #[test]
    fn test_init_zero_interval() {
        let config = SshBruteForceConfig {
            interval_secs: 0,
            ..test_config()
        };
        let mut module = SshBruteForceModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_zero_max_failures() {
        let config = SshBruteForceConfig {
            max_failures: 0,
            ..test_config()
        };
        let mut module = SshBruteForceModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_zero_time_window() {
        let config = SshBruteForceConfig {
            time_window_secs: 0,
            ..test_config()
        };
        let mut module = SshBruteForceModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid() {
        let mut module = SshBruteForceModule::new(test_config(), None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_nonexistent_path() {
        let config = SshBruteForceConfig {
            auth_log_path: PathBuf::from("/tmp/nonexistent-auth-log-test"),
            ..test_config()
        };
        let mut module = SshBruteForceModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = SshBruteForceConfig {
            auth_log_path: PathBuf::from("/tmp/nonexistent-auth-log-test"),
            ..test_config()
        };
        let mut module = SshBruteForceModule::new(config, None);
        module.init().unwrap();
        module.start().await.unwrap();
        // モジュールが起動していることを確認
        tokio::time::sleep(Duration::from_millis(50)).await;
        module.stop().await.unwrap();
    }

    #[test]
    fn test_module_name() {
        let module = SshBruteForceModule::new(test_config(), None);
        assert_eq!(module.name(), "ssh_brute_force");
    }
}
