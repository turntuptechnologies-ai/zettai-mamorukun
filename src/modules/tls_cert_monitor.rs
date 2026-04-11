//! TLS 証明書有効期限監視モジュール
//!
//! 指定ディレクトリ内の PEM 形式 TLS 証明書ファイルを定期スキャンし、
//! 有効期限が近い・期限切れの証明書を検知してアラートを発行する。
//!
//! 検知対象:
//! - 有効期限切れの証明書（Critical）
//! - 有効期限が間近の証明書（Critical / Warning）
//! - 読み取りエラーが発生したファイル（Info）

use crate::config::TlsCertMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// 単一ファイルのチェック結果
struct CertCheckResult {
    /// スナップショット文字列（"expires:YYYY-MM-DD" or "expired:YYYY-MM-DD"）
    snapshot_info: String,
    /// 問題があるかどうか（期限切れ or 閾値以内）
    is_issue: bool,
}

/// 証明書のスキャン結果
struct CertScanResult {
    /// スキャンした証明書ファイル数
    items_scanned: usize,
    /// 問題が検知された証明書数
    issues_found: usize,
    /// ファイルパス → 有効期限の文字列マップ
    snapshot: BTreeMap<String, String>,
}

/// TLS 証明書有効期限監視モジュール
pub struct TlsCertMonitorModule {
    config: TlsCertMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl TlsCertMonitorModule {
    /// 新しい TLS 証明書有効期限監視モジュールを作成する
    pub fn new(config: TlsCertMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// 指定ファイルの拡張子が監視対象か判定する
    fn has_target_extension(path: &Path, extensions: &[String]) -> bool {
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => return false,
        };
        extensions.iter().any(|ext| name.ends_with(ext.as_str()))
    }

    /// 監視対象ディレクトリをスキャンし、証明書の有効期限をチェックする
    fn scan_certs(
        watch_dirs: &[PathBuf],
        file_extensions: &[String],
        warning_days: u32,
        critical_days: u32,
        event_bus: &Option<EventBus>,
    ) -> CertScanResult {
        let mut items_scanned: usize = 0;
        let mut issues_found: usize = 0;
        let mut snapshot = BTreeMap::new();
        let now = std::time::SystemTime::now();

        for dir in watch_dirs {
            if !dir.exists() {
                tracing::debug!(dir = %dir.display(), "監視対象ディレクトリが存在しません。スキップします");
                continue;
            }

            let walker = walkdir::WalkDir::new(dir)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok());

            for entry in walker {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if !Self::has_target_extension(path, file_extensions) {
                    continue;
                }

                match Self::check_cert_file(path, now, warning_days, critical_days, event_bus) {
                    Ok(Some(check_result)) => {
                        items_scanned += 1;
                        snapshot.insert(path.display().to_string(), check_result.snapshot_info);
                        if check_result.is_issue {
                            issues_found += 1;
                        }
                    }
                    Ok(None) => {
                        // No CERTIFICATE blocks found in this PEM file
                    }
                    Err(e) => {
                        tracing::debug!(
                            path = %path.display(),
                            error = %e,
                            "証明書ファイルの読み取りに失敗しました"
                        );
                        if let Some(bus) = event_bus {
                            bus.publish(
                                SecurityEvent::new(
                                    "tls_cert_read_error",
                                    Severity::Info,
                                    "tls_cert_monitor",
                                    format!(
                                        "TLS 証明書ファイルの読み取りに失敗しました: {}",
                                        path.display()
                                    ),
                                )
                                .with_details(format!("{e}")),
                            );
                        }
                    }
                }
            }
        }

        CertScanResult {
            items_scanned,
            issues_found,
            snapshot,
        }
    }

    /// 単一の証明書ファイルをチェックし、有効期限情報を返す
    fn check_cert_file(
        path: &Path,
        now: std::time::SystemTime,
        warning_days: u32,
        critical_days: u32,
        event_bus: &Option<EventBus>,
    ) -> Result<Option<CertCheckResult>, AppError> {
        let data = std::fs::read(path).map_err(|e| AppError::FileIo {
            path: path.to_path_buf(),
            source: e,
        })?;

        let pems = pem::parse_many(&data).map_err(|e| AppError::ModuleConfig {
            message: format!("PEM パースエラー ({}): {e}", path.display()),
        })?;

        if pems.is_empty() {
            return Ok(None);
        }

        let mut result: Option<CertCheckResult> = None;

        for p in &pems {
            if p.tag() != "CERTIFICATE" {
                continue;
            }

            let (_, cert) = match x509_parser::parse_x509_certificate(p.contents()) {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(
                        path = %path.display(),
                        error = %e,
                        "X.509 証明書のパースに失敗しました"
                    );
                    continue;
                }
            };

            let not_after = cert.validity().not_after;
            let dt = not_after.to_datetime();
            let ts = dt.unix_timestamp();
            // unwrap safety: unix_timestamp from a valid x509 cert is always non-negative
            let expiry_secs = ts as u64;

            let now_secs = now
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let days_remaining = if expiry_secs >= now_secs {
                ((expiry_secs - now_secs) / 86400) as i64
            } else {
                -(((now_secs - expiry_secs) / 86400) as i64)
            };

            let date_str = format!("{:04}-{:02}-{:02}", dt.year(), dt.month() as u8, dt.day(),);

            let subject = cert
                .subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .unwrap_or("unknown");

            let (snapshot_info, is_issue) = if days_remaining < 0 {
                tracing::warn!(
                    path = %path.display(),
                    subject = subject,
                    expired_days_ago = -days_remaining,
                    "TLS 証明書の有効期限が切れています"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "tls_cert_expired",
                            Severity::Critical,
                            "tls_cert_monitor",
                            format!(
                                "TLS 証明書の有効期限が切れています: {} (CN={}、{}日前に失効)",
                                path.display(),
                                subject,
                                -days_remaining,
                            ),
                        )
                        .with_details(path.display().to_string()),
                    );
                }
                (format!("expired:{date_str}"), true)
            } else if days_remaining <= i64::from(critical_days) {
                tracing::warn!(
                    path = %path.display(),
                    subject = subject,
                    days_remaining = days_remaining,
                    "TLS 証明書の有効期限が間近です（重大）"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "tls_cert_expiring_critical",
                            Severity::Critical,
                            "tls_cert_monitor",
                            format!(
                                "TLS 証明書の有効期限が間近です: {} (CN={}、残り{}日)",
                                path.display(),
                                subject,
                                days_remaining,
                            ),
                        )
                        .with_details(path.display().to_string()),
                    );
                }
                (format!("expires:{date_str}"), true)
            } else if days_remaining <= i64::from(warning_days) {
                tracing::info!(
                    path = %path.display(),
                    subject = subject,
                    days_remaining = days_remaining,
                    "TLS 証明書の有効期限が近づいています"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "tls_cert_expiring_warning",
                            Severity::Warning,
                            "tls_cert_monitor",
                            format!(
                                "TLS 証明書の有効期限が近づいています: {} (CN={}、残り{}日)",
                                path.display(),
                                subject,
                                days_remaining,
                            ),
                        )
                        .with_details(path.display().to_string()),
                    );
                }
                (format!("expires:{date_str}"), true)
            } else {
                (format!("expires:{date_str}"), false)
            };

            // Keep the most critical result (issue takes priority over non-issue)
            match &result {
                None => {
                    result = Some(CertCheckResult {
                        snapshot_info,
                        is_issue,
                    });
                }
                Some(existing) if !existing.is_issue && is_issue => {
                    result = Some(CertCheckResult {
                        snapshot_info,
                        is_issue,
                    });
                }
                _ => {}
            }
        }

        Ok(result)
    }
}

impl Module for TlsCertMonitorModule {
    fn name(&self) -> &str {
        "tls_cert_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.check_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "check_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        for dir in &self.config.watch_dirs {
            if !dir.exists() {
                tracing::warn!(
                    dir = %dir.display(),
                    "監視対象ディレクトリが存在しません"
                );
            }
        }

        tracing::info!(
            watch_dirs = ?self.config.watch_dirs,
            check_interval_secs = self.config.check_interval_secs,
            warning_days = self.config.warning_days,
            critical_days = self.config.critical_days,
            "TLS 証明書有効期限監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let watch_dirs = self.config.watch_dirs.clone();
        let file_extensions = self.config.file_extensions.clone();
        let check_interval_secs = self.config.check_interval_secs;
        let warning_days = self.config.warning_days;
        let critical_days = self.config.critical_days;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let result = Self::scan_certs(
            &watch_dirs,
            &file_extensions,
            warning_days,
            critical_days,
            &event_bus,
        );
        tracing::info!(
            items_scanned = result.items_scanned,
            issues_found = result.issues_found,
            "TLS 証明書の初回スキャンが完了しました"
        );

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(check_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("TLS 証明書有効期限監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let result = TlsCertMonitorModule::scan_certs(
                            &watch_dirs,
                            &file_extensions,
                            warning_days,
                            critical_days,
                            &event_bus,
                        );
                        tracing::debug!(
                            items_scanned = result.items_scanned,
                            issues_found = result.issues_found,
                            "TLS 証明書の定期スキャンが完了しました"
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

        let result = Self::scan_certs(
            &self.config.watch_dirs,
            &self.config.file_extensions,
            self.config.warning_days,
            self.config.critical_days,
            &None,
        );

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned: result.items_scanned,
            issues_found: result.issues_found,
            duration,
            summary: format!(
                "TLS 証明書 {}件をスキャンしました（問題: {}件）",
                result.items_scanned, result.issues_found,
            ),
            snapshot: result.snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト用の自己署名証明書を生成する
    fn generate_test_cert_pem() -> String {
        let output = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                "/dev/null",
                "-nodes",
                "-subj",
                "/CN=test-cert",
                "-days",
                "365",
            ])
            .output()
            .expect("openssl コマンドの実行に失敗しました");
        assert!(output.status.success(), "openssl が失敗しました");
        String::from_utf8(output.stdout).unwrap()
    }

    #[test]
    fn test_init_zero_interval() {
        let config = TlsCertMonitorConfig {
            enabled: true,
            check_interval_secs: 0,
            watch_dirs: vec![],
            warning_days: 30,
            critical_days: 7,
            file_extensions: vec![".pem".to_string()],
        };
        let mut module = TlsCertMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = TlsCertMonitorConfig {
            enabled: true,
            check_interval_secs: 3600,
            watch_dirs: vec![PathBuf::from("/tmp/nonexistent-tls-test")],
            warning_days: 30,
            critical_days: 7,
            file_extensions: vec![".pem".to_string()],
        };
        let mut module = TlsCertMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_has_target_extension() {
        let exts = vec![".pem".to_string(), ".crt".to_string(), ".cer".to_string()];
        assert!(TlsCertMonitorModule::has_target_extension(
            Path::new("/etc/ssl/certs/server.pem"),
            &exts
        ));
        assert!(TlsCertMonitorModule::has_target_extension(
            Path::new("/etc/ssl/certs/server.crt"),
            &exts
        ));
        assert!(TlsCertMonitorModule::has_target_extension(
            Path::new("/etc/ssl/certs/server.cer"),
            &exts
        ));
        assert!(!TlsCertMonitorModule::has_target_extension(
            Path::new("/etc/ssl/certs/server.key"),
            &exts
        ));
        assert!(!TlsCertMonitorModule::has_target_extension(
            Path::new("/etc/ssl/certs/server.txt"),
            &exts
        ));
    }

    #[test]
    fn test_scan_empty_directory() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let result = TlsCertMonitorModule::scan_certs(
            &[tmpdir.path().to_path_buf()],
            &[".pem".to_string()],
            30,
            7,
            &None,
        );
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
        assert!(result.snapshot.is_empty());
    }

    #[test]
    fn test_scan_nonexistent_directory() {
        let result = TlsCertMonitorModule::scan_certs(
            &[PathBuf::from("/tmp/nonexistent-zettai-tls-dir-12345")],
            &[".pem".to_string()],
            30,
            7,
            &None,
        );
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[test]
    fn test_check_cert_file_expired() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let cert_path = tmpdir.path().join("test.pem");
        let pem = generate_test_cert_pem();
        std::fs::write(&cert_path, &pem).unwrap();

        // Set "now" to 2 years in the future so the 365-day cert is expired
        let future_now =
            std::time::SystemTime::now() + std::time::Duration::from_secs(2 * 365 * 86400);

        let result =
            TlsCertMonitorModule::check_cert_file(&cert_path, future_now, 30, 7, &None).unwrap();

        assert!(result.is_some());
        let check = result.unwrap();
        assert!(check.is_issue);
        assert!(
            check.snapshot_info.starts_with("expired:"),
            "expected expired: prefix, got: {}",
            check.snapshot_info
        );
    }

    #[test]
    fn test_check_cert_file_critical() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let cert_path = tmpdir.path().join("test.pem");
        let pem = generate_test_cert_pem();
        std::fs::write(&cert_path, &pem).unwrap();

        // Set "now" to 362 days in the future (3 days before 365-day cert expires)
        let future_now = std::time::SystemTime::now() + std::time::Duration::from_secs(362 * 86400);

        let result =
            TlsCertMonitorModule::check_cert_file(&cert_path, future_now, 30, 7, &None).unwrap();

        assert!(result.is_some());
        let check = result.unwrap();
        assert!(check.is_issue);
        assert!(
            check.snapshot_info.starts_with("expires:"),
            "expected expires: prefix, got: {}",
            check.snapshot_info
        );
    }

    #[test]
    fn test_check_cert_file_warning() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let cert_path = tmpdir.path().join("test.pem");
        let pem = generate_test_cert_pem();
        std::fs::write(&cert_path, &pem).unwrap();

        // Set "now" to 345 days in the future (20 days before 365-day cert expires)
        let future_now = std::time::SystemTime::now() + std::time::Duration::from_secs(345 * 86400);

        let result =
            TlsCertMonitorModule::check_cert_file(&cert_path, future_now, 30, 7, &None).unwrap();

        assert!(result.is_some());
        let check = result.unwrap();
        assert!(check.is_issue);
        assert!(check.snapshot_info.starts_with("expires:"));
    }

    #[test]
    fn test_check_cert_file_ok() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let cert_path = tmpdir.path().join("test.pem");
        let pem = generate_test_cert_pem();
        std::fs::write(&cert_path, &pem).unwrap();

        let result = TlsCertMonitorModule::check_cert_file(
            &cert_path,
            std::time::SystemTime::now(),
            30,
            7,
            &None,
        )
        .unwrap();

        assert!(result.is_some());
        let check = result.unwrap();
        assert!(!check.is_issue);
        assert!(check.snapshot_info.starts_with("expires:"));
    }

    #[test]
    fn test_scan_valid_cert() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let cert_path = tmpdir.path().join("valid.pem");
        let pem = generate_test_cert_pem();
        std::fs::write(&cert_path, &pem).unwrap();

        let result = TlsCertMonitorModule::scan_certs(
            &[tmpdir.path().to_path_buf()],
            &[".pem".to_string()],
            30,
            7,
            &None,
        );
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 0);
        assert_eq!(result.snapshot.len(), 1);
    }

    #[test]
    fn test_scan_file_extension_filtering() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let pem = generate_test_cert_pem();

        // .pem file — should be scanned
        std::fs::write(tmpdir.path().join("server.pem"), &pem).unwrap();

        // .key file — should be skipped due to extension
        std::fs::write(tmpdir.path().join("server.key"), &pem).unwrap();

        let result = TlsCertMonitorModule::scan_certs(
            &[tmpdir.path().to_path_buf()],
            &[".pem".to_string(), ".crt".to_string()],
            30,
            7,
            &None,
        );
        assert_eq!(result.items_scanned, 1);
    }

    #[test]
    fn test_scan_invalid_pem_content() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let cert_path = tmpdir.path().join("invalid.pem");
        std::fs::write(&cert_path, "this is not a valid PEM file").unwrap();

        let result = TlsCertMonitorModule::scan_certs(
            &[tmpdir.path().to_path_buf()],
            &[".pem".to_string()],
            30,
            7,
            &None,
        );
        assert_eq!(result.items_scanned, 0);
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let config = TlsCertMonitorConfig {
            enabled: true,
            check_interval_secs: 3600,
            watch_dirs: vec![tmpdir.path().to_path_buf()],
            warning_days: 30,
            critical_days: 7,
            file_extensions: vec![".pem".to_string()],
        };
        let mut module = TlsCertMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan_with_valid_cert() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let cert_path = tmpdir.path().join("test.pem");
        let pem = generate_test_cert_pem();
        std::fs::write(&cert_path, &pem).unwrap();

        let config = TlsCertMonitorConfig {
            enabled: true,
            check_interval_secs: 3600,
            watch_dirs: vec![tmpdir.path().to_path_buf()],
            warning_days: 30,
            critical_days: 7,
            file_extensions: vec![".pem".to_string()],
        };
        let module = TlsCertMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("1件をスキャン"));
    }

    #[tokio::test]
    async fn test_initial_scan_empty_dirs() {
        let config = TlsCertMonitorConfig {
            enabled: true,
            check_interval_secs: 3600,
            watch_dirs: vec![],
            warning_days: 30,
            critical_days: 7,
            file_extensions: vec![".pem".to_string()],
        };
        let module = TlsCertMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[test]
    fn test_default_config() {
        let config = TlsCertMonitorConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.check_interval_secs, 3600);
        assert_eq!(config.warning_days, 30);
        assert_eq!(config.critical_days, 7);
        assert_eq!(config.watch_dirs.len(), 2);
        assert_eq!(config.file_extensions.len(), 3);
    }
}
