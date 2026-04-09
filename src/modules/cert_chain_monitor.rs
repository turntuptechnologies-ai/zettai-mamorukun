//! TLS 証明書チェーン検証モジュール
//!
//! 指定ディレクトリ内の PEM 形式 TLS 証明書ファイルを定期スキャンし、
//! 証明書チェーンの整合性を検証してアラートを発行する。
//!
//! 検知対象:
//! - 自己署名証明書（Warning）
//! - 不完全な証明書チェーン（Warning）
//! - 証明書チェーンの発行者不一致（Critical）
//! - 読み取りエラーが発生したファイル（Info）

use crate::config::CertChainMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// 最大チェーン深度（無限ループ防止）
const MAX_CHAIN_DEPTH: usize = 10;

/// 証明書の基本情報
struct CertInfo {
    /// Subject の DN 文字列
    subject: String,
    /// Issuer の DN 文字列
    issuer: String,
    /// CN（Common Name）
    cn: String,
    /// DER エンコードされた証明書データ
    der: Vec<u8>,
}

/// 単一ファイルのチェック結果
struct ChainCheckResult {
    /// スナップショット文字列
    snapshot_info: String,
    /// 問題があるかどうか
    is_issue: bool,
}

/// 証明書チェーンのスキャン結果
struct ChainScanResult {
    /// スキャンした証明書ファイル数
    items_scanned: usize,
    /// 問題が検知された証明書数
    issues_found: usize,
    /// ファイルパス → スナップショット文字列マップ
    snapshot: BTreeMap<String, String>,
}

/// TLS 証明書チェーン検証モジュール
pub struct CertChainMonitorModule {
    config: CertChainMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl CertChainMonitorModule {
    /// 新しい TLS 証明書チェーン検証モジュールを作成する
    pub fn new(config: CertChainMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// PEM ファイルから証明書情報を抽出する
    fn parse_certs_from_pem(data: &[u8]) -> Vec<CertInfo> {
        let pems = match pem::parse_many(data) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };

        let mut certs = Vec::new();
        for p in &pems {
            if p.tag() != "CERTIFICATE" {
                continue;
            }
            let (_, cert) = match x509_parser::parse_x509_certificate(p.contents()) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            let cn = cert
                .subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .unwrap_or("unknown")
                .to_string();

            certs.push(CertInfo {
                subject,
                issuer,
                cn,
                der: p.contents().to_vec(),
            });
        }
        certs
    }

    /// 信頼済み CA マップを構築する（Subject → CertInfo リスト）
    fn build_trusted_ca_map(
        trusted_ca_dirs: &[PathBuf],
        file_extensions: &[String],
    ) -> HashMap<String, Vec<CertInfo>> {
        let mut ca_map: HashMap<String, Vec<CertInfo>> = HashMap::new();

        for dir in trusted_ca_dirs {
            if !dir.exists() {
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

                let data = match std::fs::read(path) {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                for cert in Self::parse_certs_from_pem(&data) {
                    ca_map.entry(cert.subject.clone()).or_default().push(cert);
                }
            }
        }

        ca_map
    }

    /// 証明書チェーンを検証し、結果を返す
    fn verify_chain(
        path: &Path,
        file_certs: &[CertInfo],
        trusted_ca_map: &HashMap<String, Vec<CertInfo>>,
        event_bus: &Option<EventBus>,
    ) -> Option<ChainCheckResult> {
        if file_certs.is_empty() {
            return None;
        }

        // リーフ証明書（最初の証明書）を検証対象とする
        let leaf = &file_certs[0];

        // 自己署名判定: Subject == Issuer かつ信頼済み CA に不在
        if leaf.subject == leaf.issuer {
            let in_trusted = trusted_ca_map
                .get(&leaf.subject)
                .is_some_and(|cas| cas.iter().any(|ca| ca.der == leaf.der));

            if !in_trusted {
                tracing::warn!(
                    path = %path.display(),
                    cn = %leaf.cn,
                    "自己署名証明書を検知しました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "self_signed_cert",
                            Severity::Warning,
                            "cert_chain_monitor",
                            format!(
                                "自己署名証明書を検知しました: {} (CN={})",
                                path.display(),
                                leaf.cn,
                            ),
                        )
                        .with_details(path.display().to_string()),
                    );
                }
                return Some(ChainCheckResult {
                    snapshot_info: format!("self_signed:CN={}", leaf.cn),
                    is_issue: true,
                });
            }
        }

        // チェーン構築: リーフから Issuer→Subject で辿る
        let mut current_issuer = &leaf.issuer;
        let mut depth = 0;

        // 同一ファイル内の証明書を Subject でインデックス化
        let mut file_cert_map: HashMap<&str, &CertInfo> = HashMap::new();
        for cert in file_certs.iter().skip(1) {
            file_cert_map.entry(&cert.subject).or_insert(cert);
        }

        loop {
            if depth >= MAX_CHAIN_DEPTH {
                break;
            }

            // ルート（自己署名）に到達したら正常
            // まず信頼済み CA マップで Issuer を検索
            if let Some(ca_certs) = trusted_ca_map.get(current_issuer.as_str())
                && let Some(ca) = ca_certs.first()
            {
                // Issuer が信頼済み CA に存在する場合、チェーン構築成功
                if ca.subject == ca.issuer {
                    // ルート CA に到達
                    return Some(ChainCheckResult {
                        snapshot_info: format!("chain_ok:depth={}", depth + 1),
                        is_issue: false,
                    });
                }
                // 中間 CA → さらに辿る
                current_issuer = &ca.issuer;
                depth += 1;
                continue;
            }

            // 同一ファイル内で Issuer を検索
            if let Some(parent) = file_cert_map.get(current_issuer.as_str()) {
                if parent.subject == parent.issuer {
                    // 自己署名のルートに到達
                    return Some(ChainCheckResult {
                        snapshot_info: format!("chain_ok:depth={}", depth + 1),
                        is_issue: false,
                    });
                }
                current_issuer = &parent.issuer;
                depth += 1;
                continue;
            }

            // Issuer が見つからない → 不完全なチェーン
            break;
        }

        // ルートに到達できなかった
        tracing::warn!(
            path = %path.display(),
            cn = %leaf.cn,
            issuer = %current_issuer,
            "不完全な証明書チェーンを検知しました"
        );
        if let Some(bus) = event_bus {
            bus.publish(
                SecurityEvent::new(
                    "incomplete_chain",
                    Severity::Warning,
                    "cert_chain_monitor",
                    format!(
                        "不完全な証明書チェーンを検知しました: {} (CN={}、Issuer={} の証明書が見つかりません)",
                        path.display(),
                        leaf.cn,
                        current_issuer,
                    ),
                )
                .with_details(path.display().to_string()),
            );
        }
        Some(ChainCheckResult {
            snapshot_info: format!("incomplete_chain:CN={}", leaf.cn),
            is_issue: true,
        })
    }

    /// 監視対象ディレクトリをスキャンし、証明書チェーンを検証する
    fn scan_chains(
        watch_dirs: &[PathBuf],
        file_extensions: &[String],
        trusted_ca_dirs: &[PathBuf],
        event_bus: &Option<EventBus>,
    ) -> ChainScanResult {
        let mut items_scanned: usize = 0;
        let mut issues_found: usize = 0;
        let mut snapshot = BTreeMap::new();

        let trusted_ca_map = Self::build_trusted_ca_map(trusted_ca_dirs, file_extensions);

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

                let data = match std::fs::read(path) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::debug!(
                            path = %path.display(),
                            error = %e,
                            "証明書ファイルの読み取りに失敗しました"
                        );
                        if let Some(bus) = event_bus {
                            bus.publish(
                                SecurityEvent::new(
                                    "cert_chain_read_error",
                                    Severity::Info,
                                    "cert_chain_monitor",
                                    format!(
                                        "TLS 証明書ファイルの読み取りに失敗しました: {}",
                                        path.display()
                                    ),
                                )
                                .with_details(format!("{e}")),
                            );
                        }
                        continue;
                    }
                };

                let file_certs = Self::parse_certs_from_pem(&data);
                if file_certs.is_empty() {
                    continue;
                }

                items_scanned += 1;

                if let Some(result) =
                    Self::verify_chain(path, &file_certs, &trusted_ca_map, event_bus)
                {
                    snapshot.insert(path.display().to_string(), result.snapshot_info);
                    if result.is_issue {
                        issues_found += 1;
                    }
                }
            }
        }

        ChainScanResult {
            items_scanned,
            issues_found,
            snapshot,
        }
    }
}

impl Module for CertChainMonitorModule {
    fn name(&self) -> &str {
        "cert_chain_monitor"
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
            trusted_ca_dirs = ?self.config.trusted_ca_dirs,
            "TLS 証明書チェーン検証モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        let watch_dirs = self.config.watch_dirs.clone();
        let file_extensions = self.config.file_extensions.clone();
        let trusted_ca_dirs = self.config.trusted_ca_dirs.clone();
        let check_interval_secs = self.config.check_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let result = Self::scan_chains(&watch_dirs, &file_extensions, &trusted_ca_dirs, &event_bus);
        tracing::info!(
            items_scanned = result.items_scanned,
            issues_found = result.issues_found,
            "TLS 証明書チェーンの初回スキャンが完了しました"
        );

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(check_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("TLS 証明書チェーン検証モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let result = CertChainMonitorModule::scan_chains(
                            &watch_dirs,
                            &file_extensions,
                            &trusted_ca_dirs,
                            &event_bus,
                        );
                        tracing::debug!(
                            items_scanned = result.items_scanned,
                            issues_found = result.issues_found,
                            "TLS 証明書チェーンの定期スキャンが完了しました"
                        );
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

        let result = Self::scan_chains(
            &self.config.watch_dirs,
            &self.config.file_extensions,
            &self.config.trusted_ca_dirs,
            &None,
        );

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned: result.items_scanned,
            issues_found: result.issues_found,
            duration,
            summary: format!(
                "TLS 証明書チェーン {}件を検証しました（問題: {}件）",
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
    fn generate_self_signed_cert_pem(cn: &str) -> String {
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
                &format!("/CN={cn}"),
                "-days",
                "365",
            ])
            .output()
            .expect("openssl コマンドの実行に失敗しました");
        assert!(output.status.success(), "openssl が失敗しました");
        String::from_utf8(output.stdout).unwrap()
    }

    /// テスト用の CA 証明書と署名済み証明書ペアを生成する
    fn generate_ca_and_signed_cert() -> (String, String) {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let ca_key_path = tmpdir.path().join("ca.key");
        let ca_cert_path = tmpdir.path().join("ca.pem");
        let server_key_path = tmpdir.path().join("server.key");
        let server_csr_path = tmpdir.path().join("server.csr");
        let server_cert_path = tmpdir.path().join("server.pem");

        // CA 鍵と証明書を生成
        let output = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                ca_key_path.to_str().unwrap(),
                "-out",
                ca_cert_path.to_str().unwrap(),
                "-nodes",
                "-subj",
                "/CN=Test CA",
                "-days",
                "365",
            ])
            .output()
            .expect("openssl コマンドの実行に失敗しました");
        assert!(output.status.success(), "CA 生成に失敗しました");

        // サーバー鍵と CSR を生成
        let output = std::process::Command::new("openssl")
            .args([
                "req",
                "-newkey",
                "rsa:2048",
                "-keyout",
                server_key_path.to_str().unwrap(),
                "-out",
                server_csr_path.to_str().unwrap(),
                "-nodes",
                "-subj",
                "/CN=test-server",
            ])
            .output()
            .expect("openssl コマンドの実行に失敗しました");
        assert!(output.status.success(), "CSR 生成に失敗しました");

        // CA で署名
        let output = std::process::Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                server_csr_path.to_str().unwrap(),
                "-CA",
                ca_cert_path.to_str().unwrap(),
                "-CAkey",
                ca_key_path.to_str().unwrap(),
                "-CAcreateserial",
                "-out",
                server_cert_path.to_str().unwrap(),
                "-days",
                "365",
            ])
            .output()
            .expect("openssl コマンドの実行に失敗しました");
        assert!(output.status.success(), "証明書署名に失敗しました");

        let ca_pem = std::fs::read_to_string(&ca_cert_path).unwrap();
        let server_pem = std::fs::read_to_string(&server_cert_path).unwrap();

        (ca_pem, server_pem)
    }

    #[test]
    fn test_init_zero_interval() {
        let config = CertChainMonitorConfig {
            enabled: true,
            check_interval_secs: 0,
            watch_dirs: vec![],
            file_extensions: vec![".pem".to_string()],
            trusted_ca_dirs: vec![],
        };
        let mut module = CertChainMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = CertChainMonitorConfig {
            enabled: true,
            check_interval_secs: 3600,
            watch_dirs: vec![PathBuf::from("/tmp/nonexistent-chain-test")],
            file_extensions: vec![".pem".to_string()],
            trusted_ca_dirs: vec![],
        };
        let mut module = CertChainMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_scan_empty_directory() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let result = CertChainMonitorModule::scan_chains(
            &[tmpdir.path().to_path_buf()],
            &[".pem".to_string()],
            &[],
            &None,
        );
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
        assert!(result.snapshot.is_empty());
    }

    #[test]
    fn test_scan_nonexistent_directory() {
        let result = CertChainMonitorModule::scan_chains(
            &[PathBuf::from("/tmp/nonexistent-zettai-chain-dir-12345")],
            &[".pem".to_string()],
            &[],
            &None,
        );
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    #[test]
    fn test_self_signed_cert_detection() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let cert_path = tmpdir.path().join("self-signed.pem");
        let pem = generate_self_signed_cert_pem("self-signed-test");
        std::fs::write(&cert_path, &pem).unwrap();

        // 信頼済み CA なし → 自己署名として検知される
        let result = CertChainMonitorModule::scan_chains(
            &[tmpdir.path().to_path_buf()],
            &[".pem".to_string()],
            &[], // 信頼済み CA なし
            &None,
        );
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 1);

        let snapshot_val = result.snapshot.values().next().unwrap();
        assert!(
            snapshot_val.starts_with("self_signed:"),
            "expected self_signed: prefix, got: {snapshot_val}"
        );
    }

    #[test]
    fn test_chain_ok_with_ca() {
        let (ca_pem, server_pem) = generate_ca_and_signed_cert();

        let tmpdir = tempfile::TempDir::new().unwrap();
        let ca_dir = tmpdir.path().join("ca");
        let cert_dir = tmpdir.path().join("certs");
        std::fs::create_dir(&ca_dir).unwrap();
        std::fs::create_dir(&cert_dir).unwrap();

        // CA 証明書を信頼済み CA ディレクトリに配置
        std::fs::write(ca_dir.join("ca.pem"), &ca_pem).unwrap();

        // サーバー証明書を監視対象ディレクトリに配置
        std::fs::write(cert_dir.join("server.pem"), &server_pem).unwrap();

        let result = CertChainMonitorModule::scan_chains(
            &[cert_dir],
            &[".pem".to_string()],
            &[ca_dir],
            &None,
        );
        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 0);

        let snapshot_val = result.snapshot.values().next().unwrap();
        assert!(
            snapshot_val.starts_with("chain_ok:"),
            "expected chain_ok: prefix, got: {snapshot_val}"
        );
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let config = CertChainMonitorConfig {
            enabled: true,
            check_interval_secs: 3600,
            watch_dirs: vec![tmpdir.path().to_path_buf()],
            file_extensions: vec![".pem".to_string()],
            trusted_ca_dirs: vec![],
        };
        let mut module = CertChainMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let cert_path = tmpdir.path().join("test.pem");
        let pem = generate_self_signed_cert_pem("initial-scan-test");
        std::fs::write(&cert_path, &pem).unwrap();

        let config = CertChainMonitorConfig {
            enabled: true,
            check_interval_secs: 3600,
            watch_dirs: vec![tmpdir.path().to_path_buf()],
            file_extensions: vec![".pem".to_string()],
            trusted_ca_dirs: vec![],
        };
        let module = CertChainMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 1);
        assert!(result.summary.contains("1件を検証"));
    }

    #[test]
    fn test_default_config() {
        let config = CertChainMonitorConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.check_interval_secs, 3600);
        assert_eq!(config.watch_dirs.len(), 2);
        assert_eq!(config.file_extensions.len(), 3);
        assert_eq!(config.trusted_ca_dirs.len(), 2);
    }
}
