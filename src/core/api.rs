//! REST API サーバー
//!
//! HTTP REST API でデーモンのステータス確認、イベント検索、モジュール一覧、
//! 設定リロードをリモートから操作可能にする。
//! JSON レスポンス形式で `/api/v1/` プレフィックスのエンドポイントを提供する。

use crate::config::{ApiConfig, ApiRateLimitConfig, ApiRole, ApiTokenConfig};
use crate::core::metrics::SharedMetrics;
use crate::core::status::{MetricsSummary, StatusResponse};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
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

/// 認証結果
enum AuthResult {
    /// 認証不要（トークン未設定）
    NoAuthRequired,
    /// 認証成功（ロール付き）
    Authenticated(ApiRole),
    /// 認証失敗
    Unauthorized,
}

/// トークンバケット（IP アドレスごとのレート管理）
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// レートリミット判定結果
struct RateLimitResult {
    allowed: bool,
    limit: u32,
    remaining: u32,
    reset_secs: u64,
    retry_after: Option<f64>,
}

/// トークンバケット方式のレートリミッター
struct RateLimiter {
    buckets: HashMap<IpAddr, TokenBucket>,
    max_tokens: f64,
    refill_rate: f64,
    last_cleanup: Instant,
    cleanup_interval: std::time::Duration,
}

impl RateLimiter {
    fn new(config: &ApiRateLimitConfig) -> Self {
        Self {
            buckets: HashMap::new(),
            max_tokens: f64::from(config.burst_size),
            refill_rate: config.max_requests_per_second,
            last_cleanup: Instant::now(),
            cleanup_interval: std::time::Duration::from_secs(config.cleanup_interval_secs),
        }
    }

    fn check_rate_limit(&mut self, ip: IpAddr) -> RateLimitResult {
        let now = Instant::now();
        let bucket = self.buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: self.max_tokens,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            let remaining = bucket.tokens as u32;
            let reset_secs = if remaining < self.max_tokens as u32 {
                ((self.max_tokens - bucket.tokens) / self.refill_rate).ceil() as u64
            } else {
                0
            };
            RateLimitResult {
                allowed: true,
                limit: self.max_tokens as u32,
                remaining,
                reset_secs,
                retry_after: None,
            }
        } else {
            let deficit = 1.0 - bucket.tokens;
            let retry_after = deficit / self.refill_rate;
            let reset_secs = (self.max_tokens / self.refill_rate).ceil() as u64;
            RateLimitResult {
                allowed: false,
                limit: self.max_tokens as u32,
                remaining: 0,
                reset_secs,
                retry_after: Some(retry_after),
            }
        }
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let threshold = self.cleanup_interval * 2;
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < threshold);
        self.last_cleanup = now;
    }
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
    tokens: Arc<StdMutex<Vec<ApiTokenConfig>>>,
    rate_limiter: Arc<StdMutex<Option<RateLimiter>>>,
    rate_limit_config: ApiRateLimitConfig,
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
        let rate_limiter = if config.rate_limit.enabled {
            Some(RateLimiter::new(&config.rate_limit))
        } else {
            None
        };
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
            tokens: Arc::new(StdMutex::new(config.tokens.clone())),
            rate_limiter: Arc::new(StdMutex::new(rate_limiter)),
            rate_limit_config: config.rate_limit.clone(),
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
        let tokens = self.tokens;
        let rate_limiter = self.rate_limiter;

        // クリーンアップタスク
        if self.rate_limit_config.enabled {
            let rl_cleanup = Arc::clone(&rate_limiter);
            let cleanup_interval =
                std::time::Duration::from_secs(self.rate_limit_config.cleanup_interval_secs);
            let cancel_cleanup = cancel_token.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(cleanup_interval);
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
                            if let Some(ref mut rl) = *rl_cleanup.lock().unwrap() {
                                rl.cleanup();
                            }
                        }
                        _ = cancel_cleanup.cancelled() => {
                            break;
                        }
                    }
                }
            });
        }

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                let names = Arc::clone(&shared_module_names);
                                let metrics = shared_metrics.clone();
                                let restarts = Arc::clone(&shared_module_restarts);
                                let db_path = event_store_db_path.clone();
                                let sender = reload_sender.clone();
                                let started = started_at;
                                let toks = Arc::clone(&tokens);
                                let rl = Arc::clone(&rate_limiter);
                                let client_ip = addr.ip();
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(
                                        stream, &names, &metrics, &restarts,
                                        started, &db_path, &sender, &toks,
                                        client_ip, &rl,
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

    fn authenticate(raw: &str, tokens: &[ApiTokenConfig]) -> AuthResult {
        if tokens.is_empty() {
            return AuthResult::NoAuthRequired;
        }

        let bearer = raw.lines().find_map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("authorization:") {
                let value = line["authorization:".len()..].trim();
                if value.len() > 7 && value[..7].eq_ignore_ascii_case("bearer ") {
                    Some(value[7..].trim().to_string())
                } else {
                    None
                }
            } else {
                None
            }
        });

        let Some(token) = bearer else {
            return AuthResult::Unauthorized;
        };

        let hash = Self::hash_token(&token);

        for tc in tokens {
            if tc.token_hash == hash {
                tracing::debug!(token_name = %tc.name, "API 認証成功");
                return AuthResult::Authenticated(tc.role.clone());
            }
        }

        tracing::warn!("API 認証失敗: 不明なトークン");
        AuthResult::Unauthorized
    }

    /// トークン文字列から `sha256:<hex>` 形式のハッシュを生成する
    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let result = hasher.finalize();
        format!("sha256:{:x}", result)
    }

    fn required_role(method: &HttpMethod, path: &str) -> Option<ApiRole> {
        match (method, path) {
            (HttpMethod::Get, "/api/v1/health") => None,
            (HttpMethod::Get, "/api/v1/status")
            | (HttpMethod::Get, "/api/v1/modules")
            | (HttpMethod::Get, "/api/v1/events") => Some(ApiRole::ReadOnly),
            (HttpMethod::Post, "/api/v1/reload") => Some(ApiRole::Admin),
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        mut stream: tokio::net::TcpStream,
        shared_module_names: &Arc<StdMutex<Vec<String>>>,
        shared_metrics: &Option<Arc<StdMutex<SharedMetrics>>>,
        shared_module_restarts: &Arc<StdMutex<HashMap<String, u32>>>,
        started_at: Instant,
        event_store_db_path: &Option<String>,
        reload_sender: &mpsc::Sender<()>,
        tokens: &Arc<StdMutex<Vec<ApiTokenConfig>>>,
        client_ip: IpAddr,
        rate_limiter: &Arc<StdMutex<Option<RateLimiter>>>,
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

        // レートリミットチェック（/api/v1/health はスキップ）
        let rate_limit_check = if path != "/api/v1/health" {
            // unwrap safety: Mutex が poisoned になるのはパニック時のみ
            let mut rl_guard = rate_limiter.lock().unwrap();
            (*rl_guard)
                .as_mut()
                .map(|rl| rl.check_rate_limit(client_ip))
        } else {
            None
        };

        if let Some(ref result) = rate_limit_check
            && !result.allowed
        {
            let retry_after = result.retry_after.unwrap_or(1.0).ceil() as u64;
            let retry_after = if retry_after == 0 { 1 } else { retry_after };
            let body =
                r#"{"error":"リクエスト数が上限を超えました。しばらくしてから再試行してください"}"#;
            let response = format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nRetry-After: {}\r\nX-RateLimit-Limit: {}\r\nX-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: {}\r\n\r\n{}",
                body.len(),
                retry_after,
                result.limit,
                result.reset_secs,
                body
            );
            stream.write_all(response.as_bytes()).await?;
            stream.shutdown().await?;
            return Ok(());
        }

        let rate_limit_headers = rate_limit_check.as_ref().and_then(|result| {
            if result.allowed {
                Some(format!(
                    "X-RateLimit-Limit: {}\r\nX-RateLimit-Remaining: {}\r\nX-RateLimit-Reset: {}",
                    result.limit, result.remaining, result.reset_secs
                ))
            } else {
                None
            }
        });

        // 認証チェック
        // unwrap safety: Mutex が poisoned になるのはパニック時のみ
        let token_list = tokens.lock().unwrap().clone();
        let auth = Self::authenticate(&raw, &token_list);

        if let Some(required) = Self::required_role(&method, &path) {
            match &auth {
                AuthResult::NoAuthRequired => {}
                AuthResult::Authenticated(role) => {
                    if !role.has_permission(&required) {
                        tracing::warn!(
                            path = %path,
                            "API 認可失敗: 権限不足"
                        );
                        Self::send_error_with_headers(
                            &mut stream,
                            403,
                            "Forbidden",
                            "権限が不足しています",
                            rate_limit_headers.as_deref(),
                        )
                        .await?;
                        stream.shutdown().await?;
                        return Ok(());
                    }
                }
                AuthResult::Unauthorized => {
                    Self::send_error_with_headers(
                        &mut stream,
                        401,
                        "Unauthorized",
                        "認証が必要です",
                        rate_limit_headers.as_deref(),
                    )
                    .await?;
                    stream.shutdown().await?;
                    return Ok(());
                }
            }
        }

        let extra = rate_limit_headers.as_deref();
        match (&method, path.as_str()) {
            (HttpMethod::Get, "/api/v1/health") => {
                Self::send_json_response_with_headers(
                    &mut stream,
                    200,
                    "OK",
                    r#"{"status":"ok"}"#,
                    None,
                )
                .await?;
            }
            (HttpMethod::Get, "/api/v1/status") => {
                let body = Self::build_status_response(
                    shared_module_names,
                    shared_metrics,
                    shared_module_restarts,
                    started_at,
                );
                Self::send_json_response_with_headers(&mut stream, 200, "OK", &body, extra).await?;
            }
            (HttpMethod::Get, "/api/v1/modules") => {
                let body =
                    Self::build_modules_response(shared_module_names, shared_module_restarts);
                Self::send_json_response_with_headers(&mut stream, 200, "OK", &body, extra).await?;
            }
            (HttpMethod::Get, "/api/v1/events") => match event_store_db_path {
                Some(db_path) => match Self::build_events_response(db_path, &query_params) {
                    Ok(body) => {
                        Self::send_json_response_with_headers(&mut stream, 200, "OK", &body, extra)
                            .await?;
                    }
                    Err(e) => {
                        Self::send_error_with_headers(
                            &mut stream,
                            500,
                            "Internal Server Error",
                            &e,
                            extra,
                        )
                        .await?;
                    }
                },
                None => {
                    Self::send_error_with_headers(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        "イベントストアが無効です",
                        extra,
                    )
                    .await?;
                }
            },
            (HttpMethod::Post, "/api/v1/reload") => match reload_sender.try_send(()) {
                Ok(()) => {
                    Self::send_json_response_with_headers(
                        &mut stream,
                        200,
                        "OK",
                        r#"{"message":"リロードをトリガーしました"}"#,
                        extra,
                    )
                    .await?;
                }
                Err(e) => {
                    let msg = format!("リロードのトリガーに失敗しました: {}", e);
                    Self::send_error_with_headers(
                        &mut stream,
                        500,
                        "Internal Server Error",
                        &msg,
                        extra,
                    )
                    .await?;
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
                    Self::send_error_with_headers(
                        &mut stream,
                        405,
                        "Method Not Allowed",
                        "許可されていないメソッドです",
                        extra,
                    )
                    .await?;
                } else {
                    Self::send_error_with_headers(
                        &mut stream,
                        404,
                        "Not Found",
                        "エンドポイントが見つかりません",
                        extra,
                    )
                    .await?;
                }
            }
            (HttpMethod::Post, _) => {
                if matches!(
                    path.as_str(),
                    "/api/v1/health" | "/api/v1/status" | "/api/v1/modules" | "/api/v1/events"
                ) {
                    Self::send_error_with_headers(
                        &mut stream,
                        405,
                        "Method Not Allowed",
                        "許可されていないメソッドです",
                        extra,
                    )
                    .await?;
                } else {
                    Self::send_error_with_headers(
                        &mut stream,
                        404,
                        "Not Found",
                        "エンドポイントが見つかりません",
                        extra,
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

    async fn send_json_response_with_headers(
        stream: &mut tokio::net::TcpStream,
        status: u16,
        status_text: &str,
        body: &str,
        extra_headers: Option<&str>,
    ) -> Result<(), io::Error> {
        let extra = match extra_headers {
            Some(h) => format!("{}\r\n", h),
            None => String::new(),
        };
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n{}",
            status,
            status_text,
            body.len(),
            extra,
            body
        );
        stream.write_all(response.as_bytes()).await
    }

    async fn send_error_with_headers(
        stream: &mut tokio::net::TcpStream,
        status: u16,
        status_text: &str,
        message: &str,
        extra_headers: Option<&str>,
    ) -> Result<(), io::Error> {
        let body = format!(r#"{{"error":"{}"}}"#, Self::escape_json_string(message));
        Self::send_json_response_with_headers(stream, status, status_text, &body, extra_headers)
            .await
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
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
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
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
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
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
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
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
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
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
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
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
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
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig::default(),
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

    #[test]
    fn test_hash_token() {
        let hash = ApiServer::hash_token("my-secret-token");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
        // 同じ入力は同じハッシュ
        assert_eq!(hash, ApiServer::hash_token("my-secret-token"));
        // 異なる入力は異なるハッシュ
        assert_ne!(hash, ApiServer::hash_token("other-token"));
    }

    #[test]
    fn test_authenticate_no_tokens() {
        let raw = "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let result = ApiServer::authenticate(raw, &[]);
        assert!(matches!(result, AuthResult::NoAuthRequired));
    }

    #[test]
    fn test_authenticate_valid_token() {
        let token = "test-token-123";
        let hash = ApiServer::hash_token(token);
        let tokens = vec![ApiTokenConfig {
            name: "test".to_string(),
            token_hash: hash,
            role: ApiRole::Admin,
        }];
        let raw = format!(
            "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            token
        );
        let result = ApiServer::authenticate(&raw, &tokens);
        assert!(matches!(result, AuthResult::Authenticated(ApiRole::Admin)));
    }

    #[test]
    fn test_authenticate_invalid_token() {
        let tokens = vec![ApiTokenConfig {
            name: "test".to_string(),
            token_hash: ApiServer::hash_token("correct-token"),
            role: ApiRole::Admin,
        }];
        let raw = "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong-token\r\n\r\n";
        let result = ApiServer::authenticate(raw, &tokens);
        assert!(matches!(result, AuthResult::Unauthorized));
    }

    #[test]
    fn test_authenticate_no_header() {
        let tokens = vec![ApiTokenConfig {
            name: "test".to_string(),
            token_hash: ApiServer::hash_token("my-token"),
            role: ApiRole::ReadOnly,
        }];
        let raw = "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let result = ApiServer::authenticate(raw, &tokens);
        assert!(matches!(result, AuthResult::Unauthorized));
    }

    #[test]
    fn test_role_permissions() {
        assert!(ApiRole::Admin.has_permission(&ApiRole::Admin));
        assert!(ApiRole::Admin.has_permission(&ApiRole::ReadOnly));
        assert!(ApiRole::ReadOnly.has_permission(&ApiRole::ReadOnly));
        assert!(!ApiRole::ReadOnly.has_permission(&ApiRole::Admin));
    }

    #[test]
    fn test_required_role_for_endpoints() {
        assert!(ApiServer::required_role(&HttpMethod::Get, "/api/v1/health").is_none());
        assert_eq!(
            ApiServer::required_role(&HttpMethod::Get, "/api/v1/status"),
            Some(ApiRole::ReadOnly)
        );
        assert_eq!(
            ApiServer::required_role(&HttpMethod::Get, "/api/v1/modules"),
            Some(ApiRole::ReadOnly)
        );
        assert_eq!(
            ApiServer::required_role(&HttpMethod::Get, "/api/v1/events"),
            Some(ApiRole::ReadOnly)
        );
        assert_eq!(
            ApiServer::required_role(&HttpMethod::Post, "/api/v1/reload"),
            Some(ApiRole::Admin)
        );
    }

    fn create_auth_server(tokens: Vec<ApiTokenConfig>) -> (u16, CancellationToken) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens,
            rate_limit: ApiRateLimitConfig::default(),
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
        (port, cancel)
    }

    #[tokio::test]
    async fn test_auth_health_no_token_required() {
        let tokens = vec![ApiTokenConfig {
            name: "admin".to_string(),
            token_hash: ApiServer::hash_token("secret"),
            role: ApiRole::Admin,
        }];
        let (port, cancel) = create_auth_server(tokens);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // /health は認証不要
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

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_auth_status_requires_token() {
        let tokens = vec![ApiTokenConfig {
            name: "admin".to_string(),
            token_hash: ApiServer::hash_token("secret"),
            role: ApiRole::Admin,
        }];
        let (port, cancel) = create_auth_server(tokens);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // トークンなしで /status にアクセス → 401
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
        assert!(response.contains("HTTP/1.1 401"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_auth_status_with_valid_token() {
        let token = "my-secret-token";
        let tokens = vec![ApiTokenConfig {
            name: "admin".to_string(),
            token_hash: ApiServer::hash_token(token),
            role: ApiRole::Admin,
        }];
        let (port, cancel) = create_auth_server(tokens);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let req = format!(
            "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            token
        );
        stream.write_all(req.as_bytes()).await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 200 OK"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_auth_reload_requires_admin() {
        let token = "read-only-token";
        let tokens = vec![ApiTokenConfig {
            name: "reader".to_string(),
            token_hash: ApiServer::hash_token(token),
            role: ApiRole::ReadOnly,
        }];
        let (port, cancel) = create_auth_server(tokens);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // read_only トークンで /reload にアクセス → 403
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let req = format!(
            "POST /api/v1/reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            token
        );
        stream.write_all(req.as_bytes()).await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("HTTP/1.1 403"));

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_auth_no_tokens_allows_all() {
        let (port, cancel) = create_auth_server(Vec::new());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // トークン未設定なら認証なしでアクセス可能
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

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let config = ApiRateLimitConfig {
            enabled: true,
            max_requests_per_second: 10.0,
            burst_size: 5,
            cleanup_interval_secs: 60,
        };
        let mut rl = RateLimiter::new(&config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..5 {
            let result = rl.check_rate_limit(ip);
            assert!(result.allowed);
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let config = ApiRateLimitConfig {
            enabled: true,
            max_requests_per_second: 10.0,
            burst_size: 3,
            cleanup_interval_secs: 60,
        };
        let mut rl = RateLimiter::new(&config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..3 {
            let result = rl.check_rate_limit(ip);
            assert!(result.allowed);
        }

        let result = rl.check_rate_limit(ip);
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
        assert!(result.retry_after.is_some());
    }

    #[test]
    fn test_rate_limiter_refills_tokens() {
        let config = ApiRateLimitConfig {
            enabled: true,
            max_requests_per_second: 100.0,
            burst_size: 2,
            cleanup_interval_secs: 60,
        };
        let mut rl = RateLimiter::new(&config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // 全トークン消費
        assert!(rl.check_rate_limit(ip).allowed);
        assert!(rl.check_rate_limit(ip).allowed);
        assert!(!rl.check_rate_limit(ip).allowed);

        // 手動でバケットの last_refill を過去にずらして補充をシミュレート
        if let Some(bucket) = rl.buckets.get_mut(&ip) {
            bucket.last_refill = Instant::now() - std::time::Duration::from_millis(100);
        }

        // refill_rate=100/s, 100ms 経過 → 10 トークン補充（max_tokens=2 でクランプ）
        let result = rl.check_rate_limit(ip);
        assert!(result.allowed);
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let config = ApiRateLimitConfig {
            enabled: true,
            max_requests_per_second: 10.0,
            burst_size: 5,
            cleanup_interval_secs: 1,
        };
        let mut rl = RateLimiter::new(&config);
        let ip: IpAddr = "172.16.0.1".parse().unwrap();

        rl.check_rate_limit(ip);
        assert_eq!(rl.buckets.len(), 1);

        // last_refill を古くしてクリーンアップ対象にする
        if let Some(bucket) = rl.buckets.get_mut(&ip) {
            bucket.last_refill = Instant::now() - std::time::Duration::from_secs(10);
        }

        rl.cleanup();
        assert_eq!(rl.buckets.len(), 0);
    }

    #[tokio::test]
    async fn test_api_server_rate_limit_429() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (reload_tx, _reload_rx) = mpsc::channel::<()>(1);
        let config = ApiConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port,
            tokens: Vec::new(),
            rate_limit: ApiRateLimitConfig {
                enabled: true,
                max_requests_per_second: 1.0,
                burst_size: 2,
                cleanup_interval_secs: 60,
            },
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

        // バースト内のリクエストは許可（X-RateLimit ヘッダー付き）
        for _ in 0..2 {
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
            assert!(response.contains("X-RateLimit-Limit: 2"));
        }

        // 3 回目は 429
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
        assert!(response.contains("HTTP/1.1 429 Too Many Requests"));
        assert!(response.contains("Retry-After:"));
        assert!(response.contains("X-RateLimit-Limit: 2"));
        assert!(response.contains("X-RateLimit-Remaining: 0"));

        // /api/v1/health はレートリミット対象外
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

        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
