//! イベントストリーム — Unix ソケット経由リアルタイムイベント配信

use crate::config::EventStreamConfig;
use crate::core::event::{EventBus, SecurityEvent};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;

/// NDJSON シリアライズ用
#[derive(Debug, serde::Serialize)]
struct EventJson {
    timestamp: i64,
    severity: String,
    source_module: String,
    event_type: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl From<&SecurityEvent> for EventJson {
    fn from(event: &SecurityEvent) -> Self {
        let timestamp = event
            .timestamp
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Self {
            timestamp,
            severity: event.severity.to_string(),
            source_module: event.source_module.clone(),
            event_type: event.event_type.clone(),
            message: event.message.clone(),
            details: event.details.clone(),
        }
    }
}

/// ホットリロード対象のランタイム設定
#[derive(Debug, Clone, PartialEq)]
pub struct EventStreamRuntimeConfig {
    pub buffer_size: usize,
}

/// Unix ソケット経由でリアルタイムイベントストリームを提供するサーバー
pub struct EventStreamServer {
    socket_path: PathBuf,
    receiver: broadcast::Receiver<SecurityEvent>,
    cancel_token: CancellationToken,
    buffer_size: usize,
    config_receiver: watch::Receiver<EventStreamRuntimeConfig>,
}

impl EventStreamServer {
    /// 新しい EventStreamServer を作成する
    pub fn new(
        config: &EventStreamConfig,
        event_bus: &EventBus,
    ) -> (Self, watch::Sender<EventStreamRuntimeConfig>) {
        let runtime_config = EventStreamRuntimeConfig {
            buffer_size: config.buffer_size,
        };
        let (config_sender, config_receiver) = watch::channel(runtime_config);
        let cancel_token = CancellationToken::new();
        (
            Self {
                socket_path: PathBuf::from(&config.socket_path),
                receiver: event_bus.subscribe(),
                cancel_token,
                buffer_size: config.buffer_size,
                config_receiver,
            },
            config_sender,
        )
    }

    /// キャンセルトークンを取得する
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// イベントストリームサーバーを非同期タスクとして起動する
    pub fn spawn(self) -> Result<(), std::io::Error> {
        // 既存のソケットファイルを削除
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        // 親ディレクトリが存在しない場合は作成を試みる
        if let Some(parent) = self.socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = std::os::unix::net::UnixListener::bind(&self.socket_path)?;
        listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(listener)?;

        let socket_path = self.socket_path.clone();
        let cancel_token = self.cancel_token;
        let mut receiver = self.receiver;
        let mut buffer_size = self.buffer_size;
        let mut config_receiver = self.config_receiver;

        tokio::spawn(async move {
            let mut clients: Vec<mpsc::Sender<SecurityEvent>> = Vec::new();

            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let (tx, rx) = mpsc::channel(buffer_size);
                                clients.push(tx);
                                tokio::spawn(Self::handle_client(rx, stream));
                                tracing::debug!(
                                    clients = clients.len(),
                                    "イベントストリームクライアントが接続しました"
                                );
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "イベントストリームソケットの accept に失敗");
                            }
                        }
                    }
                    result = receiver.recv() => {
                        match result {
                            Ok(event) => {
                                // 切断済みクライアントを除去しつつ送信
                                clients.retain(|tx| {
                                    tx.try_send(event.clone()).is_ok()
                                });
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!(
                                    skipped = n,
                                    "イベントストリーム: broadcast バッファの遅延により {} イベントをスキップしました",
                                    n
                                );
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                tracing::info!("イベントバスが閉じられました。イベントストリームを停止します");
                                break;
                            }
                        }
                    }
                    Ok(()) = config_receiver.changed() => {
                        let new_config = config_receiver.borrow_and_update().clone();
                        if new_config.buffer_size != buffer_size {
                            tracing::info!(
                                old = buffer_size,
                                new = new_config.buffer_size,
                                "イベントストリームのバッファサイズを更新しました（新規接続に適用）"
                            );
                            buffer_size = new_config.buffer_size;
                        }
                    }
                    _ = cancel_token.cancelled() => {
                        tracing::info!("イベントストリームサーバーを停止します");
                        break;
                    }
                }
            }
            // ソケットファイルのクリーンアップ
            let _ = std::fs::remove_file(&socket_path);
        });

        Ok(())
    }

    /// クライアント接続を処理する
    async fn handle_client(
        mut rx: mpsc::Receiver<SecurityEvent>,
        mut stream: tokio::net::UnixStream,
    ) {
        while let Some(event) = rx.recv().await {
            let json = EventJson::from(&event);
            let line = match serde_json::to_string(&json) {
                Ok(s) => s + "\n",
                Err(_) => continue,
            };
            if stream.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    }
}

/// イベントストリームに接続し、リアルタイムでイベントを表示する
pub async fn stream_events(socket_path: &Path, format: &str) -> Result<(), String> {
    let stream = UnixStream::connect(socket_path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound
            || e.kind() == std::io::ErrorKind::ConnectionRefused
        {
            format!(
                "イベントストリームに接続できません ({})\nデーモンが起動していない、またはイベントストリームが無効の可能性があります。",
                socket_path.display()
            )
        } else {
            format!("ソケット接続エラー: {}", e)
        }
    })?;

    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        match format {
            "text" => {
                if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                    println!(
                        "[{}] [{}] {} ({}): {}",
                        event.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0),
                        event
                            .get("severity")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?"),
                        event
                            .get("event_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?"),
                        event
                            .get("source_module")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?"),
                        event.get("message").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                } else {
                    println!("{}", line);
                }
            }
            _ => println!("{}", line),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventBus, SecurityEvent, Severity};

    #[test]
    fn test_event_json_from_security_event() {
        let event = SecurityEvent::new(
            "test_event",
            Severity::Warning,
            "test_module",
            "テストメッセージ",
        );
        let json = EventJson::from(&event);
        assert_eq!(json.event_type, "test_event");
        assert_eq!(json.severity, "WARNING");
        assert_eq!(json.source_module, "test_module");
        assert_eq!(json.message, "テストメッセージ");
        assert!(json.details.is_none());
        assert!(json.timestamp > 0);
    }

    #[test]
    fn test_event_json_with_details() {
        let event = SecurityEvent::new(
            "file_modified",
            Severity::Critical,
            "file_integrity",
            "ファイル変更",
        )
        .with_details("/etc/passwd".to_string());
        let json = EventJson::from(&event);
        assert_eq!(json.details, Some("/etc/passwd".to_string()));
        assert_eq!(json.severity, "CRITICAL");
    }

    #[test]
    fn test_event_json_serialization() {
        let event = SecurityEvent::new("test", Severity::Info, "mod", "msg");
        let json = EventJson::from(&event);
        let serialized = serde_json::to_string(&json).unwrap();
        assert!(serialized.contains("\"event_type\":\"test\""));
        assert!(serialized.contains("\"severity\":\"INFO\""));
        // details が None の場合はフィールドが出力されない
        assert!(!serialized.contains("details"));
    }

    #[tokio::test]
    async fn test_event_stream_server_spawn_and_client() {
        let tmpdir = tempfile::tempdir().unwrap();
        let socket_path = tmpdir.path().join("test_events.sock");

        let config = EventStreamConfig {
            enabled: true,
            socket_path: socket_path.to_str().unwrap().to_string(),
            buffer_size: 64,
        };

        let bus = EventBus::new(128);
        let (server, _config_sender) = EventStreamServer::new(&config, &bus);
        let cancel_token = server.cancel_token();
        server.spawn().unwrap();

        // クライアント接続
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let reader = BufReader::new(stream);
        let mut lines = reader.lines();

        // クライアント接続がサーバーに処理されるまで待機
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // イベント発行
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Warning,
            "test_module",
            "テストイベント",
        ));

        // 受信確認
        let line = tokio::time::timeout(std::time::Duration::from_secs(2), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["event_type"], "test_event");
        assert_eq!(parsed["severity"], "WARNING");
        assert_eq!(parsed["source_module"], "test_module");

        cancel_token.cancel();
    }

    #[tokio::test]
    async fn test_multiple_clients() {
        let tmpdir = tempfile::tempdir().unwrap();
        let socket_path = tmpdir.path().join("multi_events.sock");

        let config = EventStreamConfig {
            enabled: true,
            socket_path: socket_path.to_str().unwrap().to_string(),
            buffer_size: 64,
        };

        let bus = EventBus::new(128);
        let (server, _config_sender) = EventStreamServer::new(&config, &bus);
        let cancel_token = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 2 クライアント接続
        let stream1 = UnixStream::connect(&socket_path).await.unwrap();
        let stream2 = UnixStream::connect(&socket_path).await.unwrap();
        let reader1 = BufReader::new(stream1);
        let reader2 = BufReader::new(stream2);
        let mut lines1 = reader1.lines();
        let mut lines2 = reader2.lines();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        bus.publish(SecurityEvent::new(
            "broadcast_event",
            Severity::Info,
            "test",
            "ブロードキャスト",
        ));

        let timeout = std::time::Duration::from_secs(2);
        let line1 = tokio::time::timeout(timeout, lines1.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let line2 = tokio::time::timeout(timeout, lines2.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let v1: serde_json::Value = serde_json::from_str(&line1).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&line2).unwrap();
        assert_eq!(v1["event_type"], "broadcast_event");
        assert_eq!(v2["event_type"], "broadcast_event");

        cancel_token.cancel();
    }

    #[tokio::test]
    async fn test_client_disconnect_cleanup() {
        let tmpdir = tempfile::tempdir().unwrap();
        let socket_path = tmpdir.path().join("disconnect_events.sock");

        let config = EventStreamConfig {
            enabled: true,
            socket_path: socket_path.to_str().unwrap().to_string(),
            buffer_size: 64,
        };

        let bus = EventBus::new(128);
        let (server, _config_sender) = EventStreamServer::new(&config, &bus);
        let cancel_token = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 接続して即切断
        {
            let _stream = UnixStream::connect(&socket_path).await.unwrap();
            // stream dropped here
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 切断後もサーバーがクラッシュしないことを確認
        bus.publish(SecurityEvent::new(
            "after_disconnect",
            Severity::Info,
            "test",
            "切断後のイベント",
        ));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 新しいクライアントが接続できることを確認
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let reader = BufReader::new(stream);
        let mut lines = reader.lines();

        // クライアント接続がサーバーに処理されるまで待機
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        bus.publish(SecurityEvent::new(
            "new_client_event",
            Severity::Info,
            "test",
            "新規クライアント",
        ));

        let line = tokio::time::timeout(std::time::Duration::from_secs(2), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["event_type"], "new_client_event");

        cancel_token.cancel();
    }
}
