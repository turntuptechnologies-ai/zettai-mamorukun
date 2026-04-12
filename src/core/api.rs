//! REST API サーバー
//!
//! HTTP REST API でデーモンのステータス確認、イベント検索、モジュール一覧、
//! 設定リロードをリモートから操作可能にする。
//! JSON レスポンス形式で `/api/v1/` プレフィックスのエンドポイントを提供する。

use crate::config::ApiConfig;
use crate::core::metrics::SharedMetrics;
use crate::core::status::{MetricsSummary, StatusResponse};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// HTTP メソッド
enum HttpMethod {
    Get,
    Post,
    Other,
}

/// REST API サーバー
pub struct ApiServer {
    bind_address: String,
    port: u16,
    shared_module_names: Arc<StdMutex<Vec<String>>>,
    shared_metrics: Option<Arc<StdMutex<SharedMetrics>>>,
    shared_module_restarts: Arc<StdMutex<HashMap<String, u32>>>,
    started_at: Instant,
    event_store_db_path: Option<String>,
    reload_sender: mpsc::Sender<()>,
    cancel_token: CancellationToken,
}

impl ApiServer {
    /// 新しい ApiServer を作成する
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &ApiConfig,
        shared_module_names: Arc<StdMutex<Vec<String>>>,
        shared_metrics: Option<Arc<StdMutex<SharedMetrics>>>,
        shared_module_restarts: Arc<StdMutex<HashMap<String, u32>>>,
        started_at: Instant,
        event_store_db_path: Option<String>,
        reload_sender: mpsc::Sender<()>,
    ) -> Self {
        Self {
            bind_address: config.bind_address.clone(),
            port: config.port,
            shared_module_names,
            shared_metrics,
            shared_module_restarts,
            started_at,
            event_store_db_path,
            reload_sender,
            cancel_token: CancellationToken::new(),
        }
    }

    /// キャンセルトークンを取得する
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// API サーバーを非同期タスクとして起動する
    pub fn spawn(self) -> Result<(), std::io::Error> {
        let addr = format!("{}:{}", self.bind_address, self.port);
        let listener = std::net::TcpListener::bind(&addr)?;
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;

        let shared_module_names = self.shared_module_names;
        let shared_metrics = self.shared_metrics;
        let shared_module_restarts = self.shared_module_restarts;
        let started_at = self.started_at;
        let event_store_db_path = self.event_store_db_path;
        let reload_sender = self.reload_sender;
        let cancel_token = self.cancel_token;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let names = Arc::clone(&shared_module_names);
                                let metrics = shared_metrics.clone();
                                let restarts = Arc::clone(&shared_module_restarts);
                                let db_path = event_store_db_path.clone();
                                let sender = reload_sender.clone();
                                let started = started_at;
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(
                                        stream, &names, &metrics, &restarts,
                                        started, &db_path, &sender,
                                    ).await {
                                        tracing::debug!(error = %e, "API 接続の処理に失敗");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "API リスナーの accept に失敗");
                            }
                        }
                    }
                    _ = cancel_token.cancelled() => {
                        tracing::info!("REST API サーバーを停止します");
                        break;
                    }
                }
            }
        });

        tracing::info!(
            bind_address = %addr,
            "REST API サーバーを起動しました"
        );
        Ok(())
    }

    async fn handle_connection(
        mut stream: tokio::net::TcpStream,
        shared_module_names: &Arc<StdMutex<Vec<String>>>,
        shared_metrics: &Option<Arc<StdMutex<SharedMetrics>>>,
        shared_module_restarts: &Arc<StdMutex<HashMap<String, u32>>>,
        started_at: Instant,
        event_store_db_path: &Option<String>,
        reload_sender: &mpsc::Sender<()>,
    ) -> Result<(), io::Error> {
        // 接続タイムアウト（スローロリス対策）
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            Self::read_request(&mut stream),
        )
        .await;

        let raw = match result {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "接続タイムアウト"));
            }
        };

        let (method, path, query_params) = Self::parse_request(&raw);

        match (&method, path.as_str()) {
            (HttpMethod::Get, "/api/v1/health") => {
                Self::send_json_response(&mut stream, 200, "OK", r#"{"status":"ok"}"#).await?;
            }
            (HttpMethod::Get, "/api/v1/status") => {
                let body = Self::build_status_response(
                    shared_module_names,
                    shared_metrics,
                    shared_module_restarts,
                    started_at,
                );
                Self::send_json_response(&mut stream, 200, "OK", &body).await?;
            }
            (HttpMethod::Get, "/api/v1/modules") => {
                let body =
                    Self::build_modules_response(shared_module_names, shared_module_restarts);
                Self::send_json_response(&mut stream, 200, "OK", &body).await?;
            }
            (HttpMethod::Get, "/api/v1/events") => match event_store_db_path {
                Some(db_path) => match Self::build_events_response(db_path, &query_params) {
                    Ok(body) => {
                        Self::send_json_response(&mut stream, 200, "OK", &body).await?;
                    }
                    Err(e) => {
                        Self::send_error(&mut stream, 500, "Internal Server Error", &e).await?;
                    }
                },
                None => {
                    Self::send_error(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "イベントストアが無効です",
                    )
                    .await?;
                }
            },
            (HttpMethod::Post, "/api/v1/reload") => match reload_sender.try_send(()) {
                Ok(()) => {
                    Self::send_json_response(
                        &mut stream,
                        200,
                        "OK",
                        r#"{"message":"リロードをトリガーしました"}"#,
                    )
                    .await?;
                }
                Err(e) => {
                    let msg = format!("リロードのトリガーに失敗しました: {}", e);
                    Self::send_error(&mut stream, 500, "Internal Server Error", &msg).await?;
                }
            },
            (HttpMethod::Get, _) | (HttpMethod::Other, _) => {
                if matches!(
                    path.as_str(),
                    "/api/v1/health"
                        | "/api/v1/status"
                        | "/api/v1/modules"
                        | "/api/v1/events"
                        | "/api/v1/reload"
                ) {
                    Self::send_error(
                        &mut stream,
                        405,
                        "Method Not Allowed",
                        "許可されていないメソッドです",
                    )
                    .await?;
                } else {
                    Self::send_error(
                        &mut stream,
                        404,
                        "Not Found",
                        "エンドポイントが見つかりません",
                    )
                    .await?;
                }
            }
            (HttpMethod::Post, _) => {
                if matches!(
                    path.as_str(),
                    "/api/v1/health" | "/api/v1/status" | "/api/v1/modules" | "/api/v1/events"
                ) {
                    Self::send_error(
                        &mut stream,
                        405,
                        "Method Not Allowed",
                        "許可されていないメソッドです",
                    )
                    .await?;
                } else {
                    Self::send_error(
                        &mut stream,
                        404,
                        "Not Found",
                        "エンドポイントが見つかりません",
                    )
                    .await?;
                }
            }
        }

        stream.shutdown().await?;
        Ok(())
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> Result<String, io::Error> {
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "空のリクエスト",
            ));
        }
        Ok(String::from_utf8_lossy(&buf[..n]).to_string())
    }

    fn parse_request(raw: &str) -> (HttpMethod, String, HashMap<String, String>) {
        let first_line = raw.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        let method = if !parts.is_empty() {
            match parts[0] {
                "GET" => HttpMethod::Get,
                "POST" => HttpMethod::Post,
                _ => HttpMethod::Other,
            }
        } else {
            HttpMethod::Other
        };

        let (path, query_params) = if parts.len() >= 2 {
            let full_path = parts[1];
            if let Some(idx) = full_path.find('?') {
                let path = full_path[..idx].to_string();
                let query_str = &full_path[idx + 1..];
                let params = Self::parse_query_string(query_str);
                (path, params)
            } else {
                (full_path.to_string(), HashMap::new())
            }
        } else {
            ("/".to_string(), HashMap::new())
        };

        (method, path, query_params)
    }

    fn parse_query_string(query: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            if let Some(idx) = pair.find('=') {
                let key = pair[..idx].to_string();
                let value = pair[idx + 1..].to_string();
                params.insert(key, value);
            } else {
                params.insert(pair.to_string(), String::new());
            }
        }
        params
    }

    fn build_status_response(
        shared_module_names: &Arc<StdMutex<Vec<String>>>,
        shared_metrics: &Option<Arc<StdMutex<SharedMetrics>>>,
        shared_module_restarts: &Arc<StdMutex<HashMap<String, u32>>>,
        started_at: Instant,
    ) -> String {
        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let modules = shared_module_names.lock().unwrap().clone();
        let metrics = shared_metrics.as_ref().map(|m| {
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
        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let module_restarts = shared_module_restarts.lock().unwrap().clone();

        let response = StatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: started_at.elapsed().as_secs(),
            modules,
            metrics,
            module_restarts,
        };

        // unwrap safety: StatusResponse は Serialize を実装しており、シリアライズ失敗は起こらない
        serde_json::to_string(&response)
            .unwrap_or_else(|e| format!(r#"{{"error":"シリアライズに失敗: {}"}}"#, e))
    }

    fn build_modules_response(
        shared_module_names: &Arc<StdMutex<Vec<String>>>,
        shared_module_restarts: &Arc<StdMutex<HashMap<String, u32>>>,
    ) -> String {
        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let names = shared_module_names.lock().unwrap().clone();
        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let restarts = shared_module_restarts.lock().unwrap().clone();

        let mut modules_json = Vec::new();
        for name in &names {
            let restart_count = restarts.get(name).copied().unwrap_or(0);
            modules_json.push(format!(
                r#"{{"name":"{}","restarts":{}}}"#,
                Self::escape_json_string(name),
                restart_count
            ));
        }

        format!(r#"{{"modules":[{}]}}"#, modules_json.join(","))
    }

    fn build_events_response(
        db_path: &str,
        query_params: &HashMap<String, String>,
    ) -> Result<String, String> {
        let conn = rusqlite::Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|e| format!("データベースのオープンに失敗: {}", e))?;

        let mut sql =
            "SELECT id, timestamp, severity, source_module, event_type, message, details FROM security_events WHERE 1=1"
                .to_string();
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(severity) = query_params.get("severity") {
            sql.push_str(" AND severity = ?");
            params_vec.push(Box::new(severity.clone()));
        }

        if let Some(module) = query_params.get("module") {
            sql.push_str(" AND source_module = ?");
            params_vec.push(Box::new(module.clone()));
        }

        if let Some(since) = query_params.get("since")
            && let Some(ts) = Self::parse_iso8601(since)
        {
            sql.push_str(" AND timestamp >= ?");
            params_vec.push(Box::new(ts));
        }

        if let Some(until) = query_params.get("until")
            && let Some(ts) = Self::parse_iso8601(until)
        {
            sql.push_str(" AND timestamp <= ?");
            params_vec.push(Box::new(ts));
        }

        let limit = query_params
            .get("limit")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(100)
            .min(1000);

        sql.push_str(" ORDER BY id DESC LIMIT ?");
        params_vec.push(Box::new(limit));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("クエリの準備に失敗: {}", e))?;

        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                let id: i64 = row.get(0)?;
                let timestamp: String = row.get(1)?;
                let severity: String = row.get(2)?;
                let source_module: String = row.get(3)?;
                let event_type: String = row.get(4)?;
                let message: String = row.get(5)?;
                let details: Option<String> = row.get(6)?;
                Ok((
                    id,
                    timestamp,
                    severity,
                    source_module,
                    event_type,
                    message,
                    details,
                ))
            })
            .map_err(|e| format!("クエリの実行に失敗: {}", e))?;

        let mut events_json = Vec::new();
        for row in rows {
            match row {
                Ok((id, timestamp, severity, source_module, event_type, message, details)) => {
                    let details_part = match details {
                        Some(ref d) => format!(r#","details":"{}""#, Self::escape_json_string(d)),
                        None => String::new(),
                    };
                    events_json.push(format!(
                        r#"{{"id":{},"timestamp":"{}","severity":"{}","source_module":"{}","event_type":"{}","message":"{}"{}}}"#,
                        id,
                        Self::escape_json_string(&timestamp),
                        Self::escape_json_string(&severity),
                        Self::escape_json_string(&source_module),
                        Self::escape_json_string(&event_type),
                        Self::escape_json_string(&message),
                        details_part
                    ));
                }
                Err(e) => {
                    tracing::debug!(error = %e, "イベント行の読み取りに失敗");
                }
            }
        }

        let count = events_json.len();
        Ok(format!(
            r#"{{"events":[{}],"count":{}}}"#,
            events_json.join(","),
            count
        ))
    }

    /// ISO 8601 簡易パーサー
    ///
    /// `YYYY-MM-DDTHH:MM:SSZ` または `YYYY-MM-DD` 形式のみサポート。
    fn parse_iso8601(s: &str) -> Option<String> {
        let s = s.trim();
        // YYYY-MM-DDTHH:MM:SSZ
        if s.len() == 20 && s.ends_with('Z') {
            let parts: Vec<&str> = s[..19].split('T').collect();
            if parts.len() == 2 && Self::is_valid_date(parts[0]) && Self::is_valid_time(parts[1]) {
                return Some(s[..19].to_string());
            }
        }
        // YYYY-MM-DD
        if s.len() == 10 && Self::is_valid_date(s) {
            return Some(format!("{}T00:00:00", s));
        }
        None
    }

    fn is_valid_date(s: &str) -> bool {
        if s.len() != 10 {
            return false;
        }
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 3 {
            return false;
        }
        parts[0].len() == 4
            && parts[1].len() == 2
            && parts[2].len() == 2
            && parts[0].chars().all(|c| c.is_ascii_digit())
            && parts[1].chars().all(|c| c.is_ascii_digit())
            && parts[2].chars().all(|c| c.is_ascii_digit())
    }

    fn is_valid_time(s: &str) -> bool {
        if s.len() != 8 {
            return false;
        }
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return false;
        }
        parts[0].len() == 2
            && parts[1].len() == 2
            && parts[2].len() == 2
            && parts[0].chars().all(|c| c.is_ascii_digit())
            && parts[1].chars().all(|c| c.is_ascii_digit())
            && parts[2].chars().all(|c| c.is_ascii_digit())
    }

    fn escape_json_string(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '"' => result.push_str("\\\""),
                '\\' => result.push_str("\\\\"),
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    result.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => result.push(c),
            }
        }
        result
    }

    async fn send_json_response(
        stream: &mut tokio::net::TcpStream,
        status: u16,
        status_text: &str,
        body: &str,
    ) -> Result<(), io::Error> {
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status,
            status_text,
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await
    }

    async fn send_error(
        stream: &mut tokio::net::TcpStream,
        status: u16,
        status_text: &str,
        message: &str,
    ) -> Result<(), io::Error> {
        let body = format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(message));
        Self::send_json_response(stream, status, status_text, &body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_parse_request_get() {
        let (method, path, params) =
            ApiServer::parse_request("GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(matches!(method, HttpMethod::Get));
        assert_eq!(path, "/api/v1/health");
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_request_post() {
        let (method, path, params) =
            ApiServer::parse_request("POST /api/v1/reload HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(matches!(method, HttpMethod::Post));
        assert_eq!(path, "/api/v1/reload");
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_request_with_query_params() {
        let (method, path, params) = ApiServer::parse_request(
            "GET /api/v1/events?severity=critical&limit=50 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(matches!(method, HttpMethod::Get));
        assert_eq!(path, "/api/v1/events");
        assert_eq!(params.get("severity"), Some(&"critical".to_string()));
        assert_eq!(params.get("limit"), Some(&"50".to_string()));
    }

    #[test]
    fn test_parse_iso8601_full() {
        let result = ApiServer::parse_iso8601("2024-01-15T10:30:00Z");
        assert_eq!(result, Some("2024-01-15T10:30:00".to_string()));
    }

    #[test]
    fn test_parse_iso8601_date_only() {
        let result = ApiServer::parse_iso8601("2024-01-15");
        assert_eq!(result, Some("2024-01-15T00:00:00".to_string()));
    }

    #[test]
    fn test_parse_iso8601_invalid() {
        assert_eq!(ApiServer::parse_iso8601("not-a-date"), None);
        assert_eq!(ApiServer::parse_iso8601("2024/01/15"), None);
        assert_eq!(ApiServer::parse_iso8601(""), None);
    }

    #[tokio::test]
    async fn test_api_server_health_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            reload_tx,
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains(r#"{"status":"ok"}"#));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_status_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
        };
        let modules = Arc::new(StdMutex::new(vec!["test_module".to_string()]));
        let metrics = Arc::new(StdMutex::new(SharedMetrics {
            total_events: 10,
            info_count: 5,
            warning_count: 3,
            critical_count: 2,
            module_counts: HashMap::new(),
        }));
        let server = ApiServer::new(
            &config,
            modules,
            Some(metrics),
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            reload_tx,
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("application/json"));
        assert!(response.contains("test_module"));
        assert!(response.contains(r#""total_events":10"#));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_modules_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
        };
        let modules = Arc::new(StdMutex::new(vec![
            "mod_a".to_string(),
            "mod_b".to_string(),
        ]));
        let mut restarts = HashMap::new();
        restarts.insert("mod_b".to_string(), 2);
        let server = ApiServer::new(
            &config,
            modules,
            None,
            Arc::new(StdMutex::new(restarts)),
            Instant::now(),
            None,
            reload_tx,
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/modules HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains(r#""name":"mod_a""#));
        assert!(response.contains(r#""name":"mod_b""#));
        assert!(response.contains(r#""restarts":2"#));
        assert!(response.contains(r#""restarts":0"#));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_reload_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, mut reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            reload_tx,
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"POST /api/v1/reload HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("リロードをトリガーしました"));

        // リロードシグナルが受信されたことを確認
        let received = reload_rx.try_recv();
        assert!(received.is_ok());

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_events_no_store() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None, // event_store_db_path is None
            reload_tx,
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/v1/events HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 503"));
        assert!(response.contains("イベントストアが無効です"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_404() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            reload_tx,
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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

        assert!(response.contains("HTTP/1.1 404"));
        assert!(response.contains("エンドポイントが見つかりません"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_api_server_method_not_allowed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
        };
        let server = ApiServer::new(
            &config,
            Arc::new(StdMutex::new(Vec::new())),
            None,
            Arc::new(StdMutex::new(HashMap::new())),
            Instant::now(),
            None,
            reload_tx,
        );
        let cancel = server.cancel_token();
        server.spawn().unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // POST to a GET-only endpoint
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream
            .write_all(b"POST /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(response.contains("HTTP/1.1 405"));
        assert!(response.contains("許可されていないメソッドです"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
