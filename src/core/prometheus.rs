//! Prometheus メトリクスエクスポーター
//!
//! Prometheus テキスト形式でメトリクスを HTTP エンドポイントから公開する。
//! `/metrics` エンドポイントでメトリクスを、`/health` エンドポイントでヘルスチェックを提供する。

use crate::config::PrometheusConfig;
use crate::core::metrics::SharedMetrics;
use crate::core::module_stats::ModuleStatsHandle;
use crate::core::scoring::SharedSecurityScore;
use std::fs::File;
use std::io::BufReader;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Prometheus テキスト形式のラベル値をエスケープする
///
/// ラベル値内に含まれる `\`, `"`, `\n` を安全な形式にエスケープする。
/// 参考: https://prometheus.io/docs/instrumenting/exposition_formats/
fn escape_prometheus_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn build_prometheus_tls_acceptor(
    tls_config: &crate::config::PrometheusTlsConfig,
) -> Result<tokio_rustls::TlsAcceptor, std::io::Error> {
    use rustls::ServerConfig;
    use rustls_pemfile::{certs, private_key};

    let cert_file = File::open(&tls_config.cert_file).map_err(|e| {
        std::io::Error::other(format!(
            "証明書ファイルを開けません: {}: {}",
            tls_config.cert_file, e
        ))
    })?;
    let key_file = File::open(&tls_config.key_file).map_err(|e| {
        std::io::Error::other(format!(
            "秘密鍵ファイルを開けません: {}: {}",
            tls_config.key_file, e
        ))
    })?;

    let server_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("証明書の読み込みに失敗: {}", e),
                )
            })?;

    let key = private_key(&mut BufReader::new(key_file))
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("秘密鍵の読み込みに失敗: {}", e),
            )
        })?
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "秘密鍵が見つかりません")
        })?;

    let builder =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("TLS プロトコルバージョンの設定に失敗: {}", e),
                )
            })?;

    let config = if tls_config.mtls.enabled {
        use rustls::server::WebPkiClientVerifier;

        let ca_file = File::open(&tls_config.mtls.client_ca_file).map_err(|e| {
            std::io::Error::other(format!(
                "クライアント CA 証明書ファイルを開けません: {}: {}",
                tls_config.mtls.client_ca_file, e
            ))
        })?;
        let ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            certs(&mut BufReader::new(ca_file))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("クライアント CA 証明書の読み込みに失敗: {}", e),
                    )
                })?;

        let mut client_root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            client_root_store.add(cert).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("クライアント CA 証明書の追加に失敗: {}", e),
                )
            })?;
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = if tls_config.mtls.client_auth_mode == "optional" {
            WebPkiClientVerifier::builder_with_provider(
                Arc::new(client_root_store),
                provider.clone(),
            )
            .allow_unauthenticated()
            .build()
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("mTLS クライアント検証の構築に失敗: {}", e),
                )
            })?
        } else {
            WebPkiClientVerifier::builder_with_provider(
                Arc::new(client_root_store),
                provider.clone(),
            )
            .build()
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("mTLS クライアント検証の構築に失敗: {}", e),
                )
            })?
        };

        tracing::info!(
            client_ca_file = %tls_config.mtls.client_ca_file,
            client_auth_mode = %tls_config.mtls.client_auth_mode,
            "Prometheus mTLS: 有効"
        );

        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certs, key)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("TLS 設定の構築に失敗: {}", e),
                )
            })?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(server_certs, key)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("TLS 設定の構築に失敗: {}", e),
                )
            })?
    };

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Prometheus メトリクスエクスポーター
pub struct PrometheusExporter {
    bind_address: String,
    port: u16,
    shared_metrics: Arc<StdMutex<SharedMetrics>>,
    shared_scoring: Option<Arc<StdMutex<SharedSecurityScore>>>,
    module_stats: Option<ModuleStatsHandle>,
    started_at: Instant,
    cancel_token: CancellationToken,
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    mtls_status: String,
}

impl PrometheusExporter {
    /// 新しい PrometheusExporter を作成する
    pub fn new(
        config: &PrometheusConfig,
        shared_metrics: Arc<StdMutex<SharedMetrics>>,
        started_at: Instant,
    ) -> Self {
        if config.tls.mtls.enabled && !config.tls.enabled {
            tracing::warn!(
                "Prometheus mTLS が有効ですが TLS が無効です。mTLS を機能させるには tls.enabled = true が必要です"
            );
        }

        let tls_acceptor = if config.tls.enabled {
            match build_prometheus_tls_acceptor(&config.tls) {
                Ok(acceptor) => {
                    tracing::info!(
                        cert_file = %config.tls.cert_file,
                        key_file = %config.tls.key_file,
                        "Prometheus TLS: 有効"
                    );
                    Some(Arc::new(acceptor))
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "Prometheus TLS アクセプターの構築に失敗。TLS なしで起動します"
                    );
                    None
                }
            }
        } else {
            None
        };

        let mtls_status = if tls_acceptor.is_some() && config.tls.mtls.enabled {
            config.tls.mtls.client_auth_mode.clone()
        } else {
            "disabled".to_string()
        };

        Self {
            bind_address: config.bind_address.clone(),
            port: config.port,
            shared_metrics,
            shared_scoring: None,
            module_stats: None,
            started_at,
            cancel_token: CancellationToken::new(),
            tls_acceptor,
            mtls_status,
        }
    }

    /// セキュリティスコアリングデータを設定する
    pub fn with_scoring(mut self, scoring: Option<Arc<StdMutex<SharedSecurityScore>>>) -> Self {
        self.shared_scoring = scoring;
        self
    }

    /// モジュール実行統計ハンドルを設定する
    pub fn with_module_stats(mut self, stats: Option<ModuleStatsHandle>) -> Self {
        self.module_stats = stats;
        self
    }

    /// キャンセルトークンを取得する
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// Prometheus エクスポーターを非同期タスクとして起動する
    pub fn spawn(self) -> Result<(), std::io::Error> {
        let addr = format!("{}:{}", self.bind_address, self.port);
        let listener = std::net::TcpListener::bind(&addr)?;
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;

        let shared_metrics = self.shared_metrics;
        let shared_scoring = self.shared_scoring;
        let module_stats = self.module_stats;
        let started_at = self.started_at;
        let cancel_token = self.cancel_token;
        let tls_acc = self.tls_acceptor.clone();
        let tls_enabled = self.tls_acceptor.is_some();
        let mtls_status = self.mtls_status.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let metrics = Arc::clone(&shared_metrics);
                                let scoring = shared_scoring.clone();
                                let stats = module_stats.clone();
                                let started = started_at;
                                let tls = tls_acc.clone();
                                tokio::spawn(async move {
                                    if let Some(ref acceptor) = tls {
                                        match acceptor.accept(stream).await {
                                            Ok(tls_stream) => {
                                                if let Err(e) = Self::handle_stream(tls_stream, &metrics, &scoring, &stats, started).await {
                                                    tracing::debug!(error = %e, "Prometheus TLS 接続の処理に失敗");
                                                }
                                            }
                                            Err(e) => {
                                                tracing::debug!(error = %e, "Prometheus TLS ハンドシェイクに失敗");
                                            }
                                        }
                                    } else if let Err(e) = Self::handle_stream(stream, &metrics, &scoring, &stats, started).await {
                                        tracing::debug!(error = %e, "Prometheus 接続の処理に失敗");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "Prometheus リスナーの accept に失敗");
                            }
                        }
                    }
                    _ = cancel_token.cancelled() => {
                        tracing::info!("Prometheus エクスポーターを停止します");
                        break;
                    }
                }
            }
        });

        tracing::info!(
            bind_address = %addr,
            tls = tls_enabled,
            mtls = %mtls_status,
            "Prometheus エクスポーターを起動しました"
        );
        Ok(())
    }

    async fn handle_stream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        mut stream: S,
        shared_metrics: &Arc<StdMutex<SharedMetrics>>,
        shared_scoring: &Option<Arc<StdMutex<SharedSecurityScore>>>,
        module_stats: &Option<ModuleStatsHandle>,
        started_at: Instant,
    ) -> Result<(), std::io::Error> {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            Self::read_request_from(&mut stream),
        )
        .await;

        let request_line = match result {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "接続タイムアウト",
                ));
            }
        };

        let path = Self::parse_request_path(&request_line);

        match path {
            "/metrics" => {
                let body =
                    Self::format_metrics(shared_metrics, shared_scoring, module_stats, started_at);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await?;
            }
            "/health" => {
                let body = "ok";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await?;
            }
            _ => {
                let body = "Not Found";
                let response = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await?;
            }
        }

        stream.shutdown().await?;
        Ok(())
    }

    async fn read_request_from<S: tokio::io::AsyncRead + Unpin>(
        stream: &mut S,
    ) -> Result<String, std::io::Error> {
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "空のリクエスト",
            ));
        }
        Ok(String::from_utf8_lossy(&buf[..n]).to_string())
    }

    fn parse_request_path(request: &str) -> &str {
        // "GET /metrics HTTP/1.1\r\n..." からパスを抽出
        let first_line = request.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 { parts[1] } else { "/" }
    }

    fn format_metrics(
        shared_metrics: &Arc<StdMutex<SharedMetrics>>,
        shared_scoring: &Option<Arc<StdMutex<SharedSecurityScore>>>,
        module_stats: &Option<ModuleStatsHandle>,
        started_at: Instant,
    ) -> String {
        let mut output = String::new();

        // uptime
        let uptime = started_at.elapsed().as_secs_f64();
        output.push_str("# HELP zettai_uptime_seconds デーモンの稼働時間（秒）\n");
        output.push_str("# TYPE zettai_uptime_seconds gauge\n");
        output.push_str(&format!("zettai_uptime_seconds {uptime:.1}\n"));
        output.push('\n');

        // メトリクスデータを取得
        let metrics = match shared_metrics.lock() {
            Ok(m) => m.clone(),
            Err(_) => {
                // Mutex が poisoned の場合はデフォルト値を返す
                SharedMetrics::default()
            }
        };

        // total events counter
        output.push_str("# HELP zettai_events_total セキュリティイベントの総数\n");
        output.push_str("# TYPE zettai_events_total counter\n");
        output.push_str(&format!("zettai_events_total {}\n", metrics.total_events));
        output.push('\n');

        // events by severity
        output.push_str("# HELP zettai_events_by_severity_total Severity 別のイベント数\n");
        output.push_str("# TYPE zettai_events_by_severity_total counter\n");
        output.push_str(&format!(
            "zettai_events_by_severity_total{{severity=\"info\"}} {}\n",
            metrics.info_count
        ));
        output.push_str(&format!(
            "zettai_events_by_severity_total{{severity=\"warning\"}} {}\n",
            metrics.warning_count
        ));
        output.push_str(&format!(
            "zettai_events_by_severity_total{{severity=\"critical\"}} {}\n",
            metrics.critical_count
        ));
        output.push('\n');

        // events by module
        if !metrics.module_counts.is_empty() {
            output.push_str("# HELP zettai_events_by_module_total モジュール別のイベント数\n");
            output.push_str("# TYPE zettai_events_by_module_total counter\n");
            let mut modules: Vec<_> = metrics.module_counts.iter().collect();
            modules.sort_by_key(|(k, _)| (*k).clone());
            for (module, count) in modules {
                output.push_str(&format!(
                    "zettai_events_by_module_total{{module=\"{}\"}} {}\n",
                    module, count
                ));
            }
            output.push('\n');
        }

        // モジュール実行統計（module_stats ハンドル経由）
        if let Some(stats_handle) = module_stats {
            let snapshot = stats_handle.snapshot();
            if !snapshot.is_empty() {
                output
                    .push_str("# HELP zettai_module_events_total モジュール別の検知イベント総数\n");
                output.push_str("# TYPE zettai_module_events_total counter\n");
                for stats in &snapshot {
                    output.push_str(&format!(
                        "zettai_module_events_total{{module=\"{}\"}} {}\n",
                        escape_prometheus_label(&stats.module),
                        stats.events_total
                    ));
                }
                output.push('\n');

                output.push_str(
                    "# HELP zettai_module_events_by_severity_total モジュール別・Severity別の検知イベント数\n",
                );
                output.push_str("# TYPE zettai_module_events_by_severity_total counter\n");
                for stats in &snapshot {
                    let module_label = escape_prometheus_label(&stats.module);
                    output.push_str(&format!(
                        "zettai_module_events_by_severity_total{{module=\"{}\",severity=\"info\"}} {}\n",
                        module_label, stats.events_info
                    ));
                    output.push_str(&format!(
                        "zettai_module_events_by_severity_total{{module=\"{}\",severity=\"warning\"}} {}\n",
                        module_label, stats.events_warning
                    ));
                    output.push_str(&format!(
                        "zettai_module_events_by_severity_total{{module=\"{}\",severity=\"critical\"}} {}\n",
                        module_label, stats.events_critical
                    ));
                }
                output.push('\n');

                let scan_entries: Vec<_> = snapshot
                    .iter()
                    .filter(|s| s.initial_scan_duration_ms.is_some())
                    .collect();
                if !scan_entries.is_empty() {
                    output.push_str(
                        "# HELP zettai_module_initial_scan_duration_seconds 起動時スキャンの実行時間（秒）\n",
                    );
                    output.push_str("# TYPE zettai_module_initial_scan_duration_seconds gauge\n");
                    for stats in &scan_entries {
                        if let Some(ms) = stats.initial_scan_duration_ms {
                            output.push_str(&format!(
                                "zettai_module_initial_scan_duration_seconds{{module=\"{}\"}} {:.3}\n",
                                escape_prometheus_label(&stats.module),
                                ms as f64 / 1000.0
                            ));
                        }
                    }
                    output.push('\n');

                    output.push_str(
                        "# HELP zettai_module_initial_scan_items_scanned 起動時スキャンでスキャンしたアイテム数\n",
                    );
                    output.push_str("# TYPE zettai_module_initial_scan_items_scanned gauge\n");
                    for stats in &scan_entries {
                        if let Some(items) = stats.initial_scan_items_scanned {
                            output.push_str(&format!(
                                "zettai_module_initial_scan_items_scanned{{module=\"{}\"}} {}\n",
                                escape_prometheus_label(&stats.module),
                                items
                            ));
                        }
                    }
                    output.push('\n');

                    output.push_str(
                        "# HELP zettai_module_initial_scan_issues_found 起動時スキャンで検知した問題数\n",
                    );
                    output.push_str("# TYPE zettai_module_initial_scan_issues_found gauge\n");
                    for stats in &scan_entries {
                        if let Some(issues) = stats.initial_scan_issues_found {
                            output.push_str(&format!(
                                "zettai_module_initial_scan_issues_found{{module=\"{}\"}} {}\n",
                                escape_prometheus_label(&stats.module),
                                issues
                            ));
                        }
                    }
                    output.push('\n');
                }
            }
        }

        // security score
        if let Some(scoring) = shared_scoring {
            let score_data = match scoring.lock() {
                Ok(s) => Some(s.clone()),
                Err(_) => None,
            };
            if let Some(data) = score_data {
                output.push_str(
                    "# HELP zettai_security_score_overall Overall security score (0-100)\n",
                );
                output.push_str("# TYPE zettai_security_score_overall gauge\n");
                output.push_str(&format!(
                    "zettai_security_score_overall {}\n",
                    data.overall_score
                ));
                output.push('\n');

                if !data.categories.is_empty() {
                    output.push_str("# HELP zettai_security_score_category Security score by category (0-100)\n");
                    output.push_str("# TYPE zettai_security_score_category gauge\n");
                    let mut cats: Vec<_> = data.categories.iter().collect();
                    cats.sort_by_key(|(k, _)| (*k).clone());
                    for (category, cat_score) in cats {
                        output.push_str(&format!(
                            "zettai_security_score_category{{category=\"{}\"}} {}\n",
                            category, cat_score.score
                        ));
                    }
                    output.push('\n');
                }
            }
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_parse_request_path_metrics() {
        assert_eq!(
            PrometheusExporter::parse_request_path("GET /metrics HTTP/1.1\r\n"),
            "/metrics"
        );
    }

    #[test]
    fn test_parse_request_path_health() {
        assert_eq!(
            PrometheusExporter::parse_request_path("GET /health HTTP/1.1\r\n"),
            "/health"
        );
    }

    #[test]
    fn test_parse_request_path_root() {
        assert_eq!(
            PrometheusExporter::parse_request_path("GET / HTTP/1.1\r\n"),
            "/"
        );
    }

    #[test]
    fn test_parse_request_path_empty() {
        assert_eq!(PrometheusExporter::parse_request_path(""), "/");
    }

    #[test]
    fn test_format_metrics_default() {
        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));
        let started_at = Instant::now();
        let output = PrometheusExporter::format_metrics(&shared, &None, &None, started_at);

        assert!(output.contains("# HELP zettai_uptime_seconds"));
        assert!(output.contains("# TYPE zettai_uptime_seconds gauge"));
        assert!(output.contains("# HELP zettai_events_total"));
        assert!(output.contains("# TYPE zettai_events_total counter"));
        assert!(output.contains("zettai_events_total 0"));
        assert!(output.contains("zettai_events_by_severity_total{severity=\"info\"} 0"));
        assert!(output.contains("zettai_events_by_severity_total{severity=\"warning\"} 0"));
        assert!(output.contains("zettai_events_by_severity_total{severity=\"critical\"} 0"));
        // module_counts が空の場合は by_module セクションは出力されない
        assert!(!output.contains("zettai_events_by_module_total"));
    }

    #[test]
    fn test_format_metrics_with_data() {
        let mut module_counts = HashMap::new();
        module_counts.insert("file_integrity".to_string(), 15);
        module_counts.insert("process_monitor".to_string(), 8);

        let shared = Arc::new(StdMutex::new(SharedMetrics {
            total_events: 23,
            info_count: 10,
            warning_count: 8,
            critical_count: 5,
            module_counts,
        }));
        let started_at = Instant::now();
        let output = PrometheusExporter::format_metrics(&shared, &None, &None, started_at);

        assert!(output.contains("zettai_events_total 23"));
        assert!(output.contains("zettai_events_by_severity_total{severity=\"info\"} 10"));
        assert!(output.contains("zettai_events_by_severity_total{severity=\"warning\"} 8"));
        assert!(output.contains("zettai_events_by_severity_total{severity=\"critical\"} 5"));
        assert!(output.contains("zettai_events_by_module_total{module=\"file_integrity\"} 15"));
        assert!(output.contains("zettai_events_by_module_total{module=\"process_monitor\"} 8"));
    }

    #[test]
    fn test_format_metrics_module_sorted() {
        let mut module_counts = HashMap::new();
        module_counts.insert("z_module".to_string(), 1);
        module_counts.insert("a_module".to_string(), 2);

        let shared = Arc::new(StdMutex::new(SharedMetrics {
            total_events: 3,
            info_count: 3,
            warning_count: 0,
            critical_count: 0,
            module_counts,
        }));
        let started_at = Instant::now();
        let output = PrometheusExporter::format_metrics(&shared, &None, &None, started_at);

        // a_module が z_module より前に出力される
        let a_pos = output.find("a_module").unwrap();
        let z_pos = output.find("z_module").unwrap();
        assert!(a_pos < z_pos);
    }

    #[tokio::test]
    async fn test_prometheus_exporter_spawn_and_metrics() {
        let _config = PrometheusConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port: 0, // OS が空きポートを割り当てる — ここではテスト用に直接指定
            ..Default::default()
        };

        // ポート 0 だと実際のポート取得が難しいため、動的に空きポートを取得
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let config = PrometheusConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            ..Default::default()
        };

        let mut module_counts = HashMap::new();
        module_counts.insert("test_module".to_string(), 42);

        let shared = Arc::new(StdMutex::new(SharedMetrics {
            total_events: 42,
            info_count: 30,
            warning_count: 10,
            critical_count: 2,
            module_counts,
        }));

        let exporter = PrometheusExporter::new(&config, Arc::clone(&shared), Instant::now());
        let cancel_token = exporter.cancel_token();
        exporter.spawn().unwrap();

        // サーバーが起動する時間を与える
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // /metrics エンドポイントをテスト
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("text/plain; version=0.0.4"));
        assert!(response.contains("zettai_events_total 42"));
        assert!(response.contains("zettai_events_by_severity_total{severity=\"info\"} 30"));
        assert!(response.contains("zettai_events_by_module_total{module=\"test_module\"} 42"));

        // /health エンドポイントをテスト
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("ok"));

        // 404 テスト
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 404 Not Found"));

        // サーバー停止
        cancel_token.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[test]
    fn test_prometheus_exporter_new() {
        let config = PrometheusConfig {
            enabled: true,
            bind_address: "0.0.0.0".to_string(),
            port: 9200,
            ..Default::default()
        };
        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));
        let exporter = PrometheusExporter::new(&config, shared, Instant::now());

        assert_eq!(exporter.bind_address, "0.0.0.0");
        assert_eq!(exporter.port, 9200);
    }

    #[test]
    fn test_prometheus_exporter_new_with_started_at() {
        let past = Instant::now() - std::time::Duration::from_secs(5);
        let config = PrometheusConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port: 9200,
            ..Default::default()
        };
        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));
        let exporter = PrometheusExporter::new(&config, shared, past);

        let output = PrometheusExporter::format_metrics(
            &exporter.shared_metrics,
            &None,
            &None,
            exporter.started_at,
        );
        assert!(output.contains("zettai_uptime_seconds"));
        let uptime = parse_uptime_from_metrics(&output);
        assert!(uptime >= 5.0, "uptime should be >= 5.0, got {uptime}");
    }

    #[tokio::test]
    async fn test_prometheus_exporter_restart_on_different_port() {
        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));

        // 最初のエクスポーターを空きポートで起動
        let listener1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port1 = listener1.local_addr().unwrap().port();
        drop(listener1);

        let config1 = PrometheusConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port: port1,
            ..Default::default()
        };
        let exporter1 = PrometheusExporter::new(&config1, Arc::clone(&shared), Instant::now());
        let cancel1 = exporter1.cancel_token();
        exporter1.spawn().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // cancel_token で停止
        cancel1.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 別の空きポートで新しいエクスポーターを起動
        let listener2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port2 = listener2.local_addr().unwrap().port();
        drop(listener2);

        let config2 = PrometheusConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port: port2,
            ..Default::default()
        };
        let exporter2 = PrometheusExporter::new(&config2, Arc::clone(&shared), Instant::now());
        let cancel2 = exporter2.cancel_token();
        exporter2.spawn().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 新ポートで /metrics にアクセスできることを確認
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port2}"))
            .await
            .unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("zettai_uptime_seconds"));

        cancel2.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_prometheus_exporter_started_at_preserved() {
        let past = Instant::now() - std::time::Duration::from_secs(3);
        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let config = PrometheusConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            ..Default::default()
        };
        let exporter = PrometheusExporter::new(&config, Arc::clone(&shared), past);
        let cancel = exporter.cancel_token();
        exporter.spawn().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // /metrics から uptime を取得
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        let uptime = parse_uptime_from_metrics(&response);
        assert!(
            uptime >= 3.0,
            "uptime should be >= 3.0 (started_at preserved), got {uptime}"
        );

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    fn parse_uptime_from_metrics(output: &str) -> f64 {
        for line in output.lines() {
            if line.starts_with("zettai_uptime_seconds ") {
                return line
                    .strip_prefix("zettai_uptime_seconds ")
                    .unwrap()
                    .trim()
                    .parse::<f64>()
                    .unwrap();
            }
        }
        panic!("zettai_uptime_seconds not found in metrics output");
    }

    #[test]
    fn test_prometheus_tls_config_default() {
        let tls = crate::config::PrometheusTlsConfig::default();
        assert!(!tls.enabled);
        assert!(tls.cert_file.is_empty());
        assert!(tls.key_file.is_empty());
        assert!(!tls.mtls.enabled);
    }

    #[test]
    fn test_prometheus_mtls_config_default() {
        let mtls = crate::config::PrometheusMtlsConfig::default();
        assert!(!mtls.enabled);
        assert!(mtls.client_ca_file.is_empty());
        assert_eq!(mtls.client_auth_mode, "required");
    }

    #[test]
    fn test_build_prometheus_tls_acceptor_invalid_cert_path() {
        let tls_config = crate::config::PrometheusTlsConfig {
            enabled: true,
            cert_file: "/nonexistent/cert.pem".to_string(),
            key_file: "/nonexistent/key.pem".to_string(),
            ..Default::default()
        };
        let result = build_prometheus_tls_acceptor(&tls_config);
        let err = result.err().expect("should be error");
        assert!(err.to_string().contains("証明書ファイルを開けません"));
    }

    #[test]
    fn test_build_prometheus_tls_acceptor_mtls_invalid_ca_path() {
        let tmp_dir = std::env::temp_dir();
        let cert_path = tmp_dir.join("test_prom_mtls_cert.pem");
        let key_path = tmp_dir.join("test_prom_mtls_key.pem");

        let cert_pem = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, cert_pem.cert.pem()).unwrap();
        std::fs::write(&key_path, cert_pem.key_pair.serialize_pem()).unwrap();

        let tls_config = crate::config::PrometheusTlsConfig {
            enabled: true,
            cert_file: cert_path.to_string_lossy().to_string(),
            key_file: key_path.to_string_lossy().to_string(),
            mtls: crate::config::PrometheusMtlsConfig {
                enabled: true,
                client_ca_file: "/nonexistent/ca.pem".to_string(),
                client_auth_mode: "required".to_string(),
            },
        };
        let result = build_prometheus_tls_acceptor(&tls_config);
        let err = result.err().expect("should be error");
        assert!(
            err.to_string()
                .contains("クライアント CA 証明書ファイルを開けません")
        );

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }

    #[test]
    fn test_prometheus_exporter_with_tls_disabled() {
        let config = PrometheusConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port: 9200,
            ..Default::default()
        };
        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));
        let exporter = PrometheusExporter::new(&config, shared, Instant::now());
        assert!(exporter.tls_acceptor.is_none());
        assert_eq!(exporter.mtls_status, "disabled");
    }

    #[test]
    fn test_prometheus_mtls_warning_without_tls() {
        let config = PrometheusConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port: 9200,
            tls: crate::config::PrometheusTlsConfig {
                enabled: false,
                cert_file: String::new(),
                key_file: String::new(),
                mtls: crate::config::PrometheusMtlsConfig {
                    enabled: true,
                    client_ca_file: "/some/ca.pem".to_string(),
                    client_auth_mode: "required".to_string(),
                },
            },
        };
        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));
        let exporter = PrometheusExporter::new(&config, shared, Instant::now());
        assert!(exporter.tls_acceptor.is_none());
        assert_eq!(exporter.mtls_status, "disabled");
    }

    #[test]
    fn test_prometheus_tls_config_deserialize() {
        let toml_str = r#"
            enabled = true
            cert_file = "/etc/certs/server.crt"
            key_file = "/etc/certs/server.key"
        "#;
        let config: crate::config::PrometheusTlsConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert_eq!(config.cert_file, "/etc/certs/server.crt");
        assert_eq!(config.key_file, "/etc/certs/server.key");
        assert!(!config.mtls.enabled);
    }

    #[test]
    fn test_prometheus_mtls_config_deserialize() {
        let toml_str = r#"
            enabled = true
            client_ca_file = "/etc/certs/client-ca.crt"
            client_auth_mode = "optional"
        "#;
        let config: crate::config::PrometheusMtlsConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert_eq!(config.client_ca_file, "/etc/certs/client-ca.crt");
        assert_eq!(config.client_auth_mode, "optional");
    }

    #[test]
    fn test_escape_prometheus_label_plain() {
        assert_eq!(escape_prometheus_label("file_integrity"), "file_integrity");
        assert_eq!(escape_prometheus_label(""), "");
    }

    #[test]
    fn test_escape_prometheus_label_quotes_backslash_newline() {
        assert_eq!(escape_prometheus_label(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_prometheus_label(r"a\b"), r"a\\b");
        assert_eq!(escape_prometheus_label("a\nb"), "a\\nb");
        assert_eq!(escape_prometheus_label("a\\\"\nb"), "a\\\\\\\"\\nb");
    }

    #[test]
    fn test_format_metrics_module_stats_empty_handle() {
        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));
        let handle = ModuleStatsHandle::new();
        let output =
            PrometheusExporter::format_metrics(&shared, &None, &Some(handle), Instant::now());
        // snapshot が空なのでモジュール統計セクションは出力されない
        assert!(!output.contains("zettai_module_events_total"));
        assert!(!output.contains("zettai_module_events_by_severity_total"));
        assert!(!output.contains("zettai_module_initial_scan_duration_seconds"));
    }

    #[test]
    fn test_format_metrics_module_stats_events_only() {
        use crate::core::event::{SecurityEvent, Severity};

        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));
        let handle = ModuleStatsHandle::new();
        handle.record_event(&SecurityEvent::new(
            "t",
            Severity::Info,
            "file_integrity",
            "msg",
        ));
        handle.record_event(&SecurityEvent::new(
            "t",
            Severity::Warning,
            "file_integrity",
            "msg",
        ));
        handle.record_event(&SecurityEvent::new(
            "t",
            Severity::Critical,
            "file_integrity",
            "msg",
        ));
        handle.record_event(&SecurityEvent::new("t", Severity::Info, "ssh_brute", "msg"));

        let output =
            PrometheusExporter::format_metrics(&shared, &None, &Some(handle), Instant::now());

        assert!(output.contains("# HELP zettai_module_events_total"));
        assert!(output.contains("# TYPE zettai_module_events_total counter"));
        assert!(output.contains("zettai_module_events_total{module=\"file_integrity\"} 3"));
        assert!(output.contains("zettai_module_events_total{module=\"ssh_brute\"} 1"));

        assert!(output.contains("# TYPE zettai_module_events_by_severity_total counter"));
        assert!(output.contains(
            "zettai_module_events_by_severity_total{module=\"file_integrity\",severity=\"info\"} 1"
        ));
        assert!(output.contains(
            "zettai_module_events_by_severity_total{module=\"file_integrity\",severity=\"warning\"} 1"
        ));
        assert!(output.contains(
            "zettai_module_events_by_severity_total{module=\"file_integrity\",severity=\"critical\"} 1"
        ));
        assert!(output.contains(
            "zettai_module_events_by_severity_total{module=\"ssh_brute\",severity=\"info\"} 1"
        ));

        // initial_scan セクションは未記録なので出力されない
        assert!(!output.contains("zettai_module_initial_scan_duration_seconds"));
        assert!(!output.contains("zettai_module_initial_scan_items_scanned"));
        assert!(!output.contains("zettai_module_initial_scan_issues_found"));
    }

    #[test]
    fn test_format_metrics_module_stats_initial_scan() {
        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));
        let handle = ModuleStatsHandle::new();
        handle.record_initial_scan(
            "file_integrity",
            std::time::Duration::from_millis(1234),
            500,
            3,
            "scan complete",
        );
        // 起動時スキャン記録なしのモジュールも混在
        handle.ensure("idle_module");

        let output =
            PrometheusExporter::format_metrics(&shared, &None, &Some(handle), Instant::now());

        assert!(output.contains("# TYPE zettai_module_initial_scan_duration_seconds gauge"));
        assert!(output.contains(
            "zettai_module_initial_scan_duration_seconds{module=\"file_integrity\"} 1.234"
        ));
        assert!(output.contains("# TYPE zettai_module_initial_scan_items_scanned gauge"));
        assert!(
            output.contains(
                "zettai_module_initial_scan_items_scanned{module=\"file_integrity\"} 500"
            )
        );
        assert!(output.contains("# TYPE zettai_module_initial_scan_issues_found gauge"));
        assert!(
            output.contains("zettai_module_initial_scan_issues_found{module=\"file_integrity\"} 3")
        );

        // 起動時スキャンしていない idle_module は initial_scan セクションには含まれない
        assert!(
            !output.contains("zettai_module_initial_scan_duration_seconds{module=\"idle_module\"}")
        );
        // ただしイベント未記録でもモジュール名が登録されていれば events_total では 0 として出力される
        assert!(output.contains("zettai_module_events_total{module=\"idle_module\"} 0"));
    }

    #[test]
    fn test_format_metrics_module_stats_sorted_by_module() {
        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));
        let handle = ModuleStatsHandle::new();
        handle.ensure_all(["zeta_mod", "alpha_mod", "mid_mod"]);

        let output =
            PrometheusExporter::format_metrics(&shared, &None, &Some(handle), Instant::now());

        let alpha = output.find("module=\"alpha_mod\"").expect("alpha_mod");
        let mid = output.find("module=\"mid_mod\"").expect("mid_mod");
        let zeta = output.find("module=\"zeta_mod\"").expect("zeta_mod");
        assert!(alpha < mid);
        assert!(mid < zeta);
    }

    #[test]
    fn test_with_module_stats_none_suppresses_section() {
        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));
        let output = PrometheusExporter::format_metrics(&shared, &None, &None, Instant::now());
        assert!(!output.contains("zettai_module_events_total"));
        assert!(!output.contains("zettai_module_events_by_severity_total"));
        assert!(!output.contains("zettai_module_initial_scan_"));
    }

    #[tokio::test]
    async fn test_prometheus_exporter_serves_module_stats() {
        use crate::core::event::{SecurityEvent, Severity};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let config = PrometheusConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            ..Default::default()
        };

        let handle = ModuleStatsHandle::new();
        handle.record_event(&SecurityEvent::new(
            "t",
            Severity::Critical,
            "backdoor_detector",
            "msg",
        ));
        handle.record_initial_scan(
            "backdoor_detector",
            std::time::Duration::from_millis(42),
            10,
            1,
            "scan done",
        );

        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));
        let exporter = PrometheusExporter::new(&config, shared, Instant::now())
            .with_module_stats(Some(handle));
        let cancel = exporter.cancel_token();
        exporter.spawn().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("zettai_module_events_total{module=\"backdoor_detector\"} 1"));
        assert!(response.contains(
            "zettai_module_events_by_severity_total{module=\"backdoor_detector\",severity=\"critical\"} 1"
        ));
        assert!(response.contains(
            "zettai_module_initial_scan_duration_seconds{module=\"backdoor_detector\"} 0.042"
        ));
        assert!(
            response.contains(
                "zettai_module_initial_scan_items_scanned{module=\"backdoor_detector\"} 10"
            )
        );
        assert!(
            response.contains(
                "zettai_module_initial_scan_issues_found{module=\"backdoor_detector\"} 1"
            )
        );

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
