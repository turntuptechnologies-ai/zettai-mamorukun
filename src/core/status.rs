//! CLI ステータスコマンド用 Unix ソケットサーバー・クライアント

use crate::core::metrics::SharedMetrics;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

/// ステータスレスポンス
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    /// バージョン
    pub version: String,
    /// 稼働時間（秒）
    pub uptime_secs: u64,
    /// 有効モジュール名のリスト
    pub modules: Vec<String>,
    /// メトリクスサマリー（メトリクスが無効の場合は None）
    pub metrics: Option<MetricsSummary>,
}

/// メトリクスサマリー
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsSummary {
    /// 合計イベント数
    pub total_events: u64,
    /// INFO レベルのイベント数
    pub info_count: u64,
    /// WARNING レベルのイベント数
    pub warning_count: u64,
    /// CRITICAL レベルのイベント数
    pub critical_count: u64,
    /// モジュール別イベント数
    pub module_counts: HashMap<String, u64>,
}

/// ステータスサーバーが参照するデーモン状態
pub struct DaemonState {
    started_at: Instant,
    modules: Arc<Mutex<Vec<String>>>,
    shared_metrics: Option<Arc<Mutex<SharedMetrics>>>,
}

impl DaemonState {
    /// 新しい DaemonState を作成する
    pub fn new(
        modules: Arc<Mutex<Vec<String>>>,
        shared_metrics: Option<Arc<Mutex<SharedMetrics>>>,
    ) -> Self {
        Self {
            started_at: Instant::now(),
            modules,
            shared_metrics,
        }
    }

    fn to_response(&self) -> StatusResponse {
        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let modules = self.modules.lock().unwrap().clone();
        let metrics = self.shared_metrics.as_ref().map(|m| {
            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
            let m = m.lock().unwrap();
            MetricsSummary {
                total_events: m.total_events,
                info_count: m.info_count,
                warning_count: m.warning_count,
                critical_count: m.critical_count,
                module_counts: m.module_counts.clone(),
            }
        });
        StatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            modules,
            metrics,
        }
    }
}

/// Unix ソケット経由でステータスを提供するサーバー
pub struct StatusServer {
    socket_path: PathBuf,
    state: Arc<DaemonState>,
    cancel_token: CancellationToken,
}

impl StatusServer {
    /// 新しい StatusServer を作成する
    pub fn new(socket_path: impl Into<PathBuf>, state: DaemonState) -> Self {
        Self {
            socket_path: socket_path.into(),
            state: Arc::new(state),
            cancel_token: CancellationToken::new(),
        }
    }

    /// キャンセルトークンを取得する
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// ステータスサーバーを非同期タスクとして起動する
    pub fn spawn(self) -> Result<(), std::io::Error> {
        // 既存のソケットファイルを削除
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        // 親ディレクトリが存在しない場合は作成を試みる（失敗してもOK）
        if let Some(parent) = self.socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = std::os::unix::net::UnixListener::bind(&self.socket_path)?;
        listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(listener)?;

        let socket_path = self.socket_path.clone();
        let state = self.state;
        let cancel_token = self.cancel_token;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let state = Arc::clone(&state);
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(stream, &state).await {
                                        tracing::debug!(error = %e, "ステータス接続の処理に失敗");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "ステータスソケットの accept に失敗");
                            }
                        }
                    }
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ステータスサーバーを停止します");
                        break;
                    }
                }
            }
            // ソケットファイルのクリーンアップ
            let _ = std::fs::remove_file(&socket_path);
        });

        tracing::info!(
            socket_path = %self.socket_path.display(),
            "ステータスサーバーを起動しました"
        );
        Ok(())
    }

    async fn handle_connection(
        mut stream: tokio::net::UnixStream,
        state: &DaemonState,
    ) -> Result<(), std::io::Error> {
        let response = state.to_response();
        let json = serde_json::to_vec(&response)
            .map_err(std::io::Error::other)?;
        stream.write_all(&json).await?;
        stream.shutdown().await?;
        Ok(())
    }
}

/// ステータスクライアント — CLI status コマンドから呼び出す
pub async fn query_status(socket_path: &Path) -> Result<StatusResponse, String> {
    use tokio::io::AsyncReadExt;

    let mut stream = UnixStream::connect(socket_path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound
            || e.kind() == std::io::ErrorKind::ConnectionRefused
        {
            format!(
                "デーモンに接続できません ({})\nデーモンが起動していない可能性があります。",
                socket_path.display()
            )
        } else {
            format!("ソケット接続エラー: {}", e)
        }
    })?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("読み取りエラー: {}", e))?;

    serde_json::from_slice(&buf).map_err(|e| format!("JSON パースエラー: {}", e))
}

/// ステータスレスポンスを人間が読める形式で表示する
pub fn print_status(response: &StatusResponse) {
    println!("ぜったいまもるくん v{}", response.version);
    println!("稼働時間: {} 秒", response.uptime_secs);
    println!();

    println!("有効モジュール ({} 個):", response.modules.len());
    if response.modules.is_empty() {
        println!("  (なし)");
    } else {
        for module in &response.modules {
            println!("  - {}", module);
        }
    }

    if let Some(ref metrics) = response.metrics {
        println!();
        println!("イベント統計:");
        println!("  合計: {}", metrics.total_events);
        println!("  INFO: {}", metrics.info_count);
        println!("  WARNING: {}", metrics.warning_count);
        println!("  CRITICAL: {}", metrics.critical_count);
        if !metrics.module_counts.is_empty() {
            println!();
            println!("  モジュール別:");
            let mut counts: Vec<_> = metrics.module_counts.iter().collect();
            counts.sort_by_key(|(_, v)| std::cmp::Reverse(**v));
            for (module, count) in counts {
                println!("    {}: {}", module, count);
            }
        }
    } else {
        println!();
        println!("メトリクス: 無効");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_response_serialize_deserialize() {
        let response = StatusResponse {
            version: "0.37.0".to_string(),
            uptime_secs: 120,
            modules: vec!["module_a".to_string(), "module_b".to_string()],
            metrics: Some(MetricsSummary {
                total_events: 42,
                info_count: 30,
                warning_count: 10,
                critical_count: 2,
                module_counts: HashMap::from([
                    ("module_a".to_string(), 25),
                    ("module_b".to_string(), 17),
                ]),
            }),
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: StatusResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, "0.37.0");
        assert_eq!(deserialized.uptime_secs, 120);
        assert_eq!(deserialized.modules.len(), 2);
        let metrics = deserialized.metrics.unwrap();
        assert_eq!(metrics.total_events, 42);
        assert_eq!(metrics.info_count, 30);
        assert_eq!(metrics.warning_count, 10);
        assert_eq!(metrics.critical_count, 2);
    }

    #[test]
    fn test_status_response_without_metrics() {
        let response = StatusResponse {
            version: "0.37.0".to_string(),
            uptime_secs: 60,
            modules: vec![],
            metrics: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: StatusResponse = serde_json::from_str(&json).unwrap();

        assert!(deserialized.metrics.is_none());
        assert!(deserialized.modules.is_empty());
    }

    #[test]
    fn test_daemon_state_to_response() {
        let modules = Arc::new(Mutex::new(vec![
            "module_a".to_string(),
            "module_b".to_string(),
        ]));
        let shared_metrics = Arc::new(Mutex::new(SharedMetrics {
            total_events: 10,
            info_count: 5,
            warning_count: 3,
            critical_count: 2,
            module_counts: HashMap::from([("module_a".to_string(), 10)]),
        }));

        let state = DaemonState::new(modules, Some(shared_metrics));
        let response = state.to_response();

        assert_eq!(response.modules.len(), 2);
        assert!(response.modules.contains(&"module_a".to_string()));
        let metrics = response.metrics.unwrap();
        assert_eq!(metrics.total_events, 10);
    }

    #[test]
    fn test_daemon_state_to_response_without_metrics() {
        let modules = Arc::new(Mutex::new(vec![]));
        let state = DaemonState::new(modules, None);
        let response = state.to_response();

        assert!(response.modules.is_empty());
        assert!(response.metrics.is_none());
    }

    #[test]
    fn test_print_status_does_not_panic() {
        let response = StatusResponse {
            version: "0.37.0".to_string(),
            uptime_secs: 3600,
            modules: vec!["module_a".to_string()],
            metrics: Some(MetricsSummary {
                total_events: 100,
                info_count: 80,
                warning_count: 15,
                critical_count: 5,
                module_counts: HashMap::from([("module_a".to_string(), 100)]),
            }),
        };
        // パニックしないことを確認
        print_status(&response);
    }

    #[test]
    fn test_print_status_without_metrics_does_not_panic() {
        let response = StatusResponse {
            version: "0.37.0".to_string(),
            uptime_secs: 0,
            modules: vec![],
            metrics: None,
        };
        // パニックしないことを確認
        print_status(&response);
    }

    #[tokio::test]
    async fn test_status_server_and_client() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("test_status.sock");

        let modules = Arc::new(Mutex::new(vec!["test_module".to_string()]));
        let shared_metrics = Arc::new(Mutex::new(SharedMetrics {
            total_events: 5,
            info_count: 3,
            warning_count: 1,
            critical_count: 1,
            module_counts: HashMap::from([("test_module".to_string(), 5)]),
        }));

        let state = DaemonState::new(modules, Some(shared_metrics));
        let server = StatusServer::new(&socket_path, state);
        let cancel_token = server.cancel_token();
        server.spawn().unwrap();

        // サーバーが起動する時間を与える
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // クライアントで接続
        let response = query_status(&socket_path).await.unwrap();
        assert_eq!(response.modules, vec!["test_module".to_string()]);
        let metrics = response.metrics.unwrap();
        assert_eq!(metrics.total_events, 5);

        // サーバー停止
        cancel_token.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_query_status_connection_refused() {
        let result = query_status(Path::new("/tmp/nonexistent-zettai-status.sock")).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("デーモンに接続できません") || err.contains("ソケット接続エラー"));
    }
}
