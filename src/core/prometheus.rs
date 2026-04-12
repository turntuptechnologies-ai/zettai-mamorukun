//! Prometheus メトリクスエクスポーター
//!
//! Prometheus テキスト形式でメトリクスを HTTP エンドポイントから公開する。
//! `/metrics` エンドポイントでメトリクスを、`/health` エンドポイントでヘルスチェックを提供する。

use crate::config::PrometheusConfig;
use crate::core::metrics::SharedMetrics;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Prometheus メトリクスエクスポーター
pub struct PrometheusExporter {
    bind_address: String,
    port: u16,
    shared_metrics: Arc<StdMutex<SharedMetrics>>,
    started_at: Instant,
    cancel_token: CancellationToken,
}

impl PrometheusExporter {
    /// 新しい PrometheusExporter を作成する
    pub fn new(config: &PrometheusConfig, shared_metrics: Arc<StdMutex<SharedMetrics>>) -> Self {
        Self {
            bind_address: config.bind_address.clone(),
            port: config.port,
            shared_metrics,
            started_at: Instant::now(),
            cancel_token: CancellationToken::new(),
        }
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
        let started_at = self.started_at;
        let cancel_token = self.cancel_token;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let metrics = Arc::clone(&shared_metrics);
                                let started = started_at;
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(stream, &metrics, started).await {
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
            "Prometheus エクスポーターを起動しました"
        );
        Ok(())
    }

    async fn handle_connection(
        mut stream: tokio::net::TcpStream,
        shared_metrics: &Arc<StdMutex<SharedMetrics>>,
        started_at: Instant,
    ) -> Result<(), std::io::Error> {
        // 接続タイムアウト（スローロリス対策）
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            Self::read_request(&mut stream),
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
                let body = Self::format_metrics(shared_metrics, started_at);
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

    async fn read_request(stream: &mut tokio::net::TcpStream) -> Result<String, std::io::Error> {
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
        let output = PrometheusExporter::format_metrics(&shared, started_at);

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
        let output = PrometheusExporter::format_metrics(&shared, started_at);

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
        let output = PrometheusExporter::format_metrics(&shared, started_at);

        // a_module が z_module より前に出力される
        let a_pos = output.find("a_module").unwrap();
        let z_pos = output.find("z_module").unwrap();
        assert!(a_pos < z_pos);
    }

    #[tokio::test]
    async fn test_prometheus_exporter_spawn_and_metrics() {
        let config = PrometheusConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port: 0, // OS が空きポートを割り当てる — ここではテスト用に直接指定
        };

        // ポート 0 だと実際のポート取得が難しいため、動的に空きポートを取得
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let config = PrometheusConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
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

        let exporter = PrometheusExporter::new(&config, Arc::clone(&shared));
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
        };
        let shared = Arc::new(StdMutex::new(SharedMetrics::default()));
        let exporter = PrometheusExporter::new(&config, shared);

        assert_eq!(exporter.bind_address, "0.0.0.0");
        assert_eq!(exporter.port, 9200);
    }
}
