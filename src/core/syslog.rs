//! Syslog イベント転送 — RFC 5424 形式で外部 SIEM に SecurityEvent を転送

use crate::config::SyslogConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use std::time::SystemTime;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{broadcast, watch};

/// ホットリロード対象のランタイム設定
#[derive(Debug, Clone)]
pub struct SyslogRuntimeConfig {
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub facility: String,
    pub hostname: String,
    pub app_name: String,
}

impl From<&SyslogConfig> for SyslogRuntimeConfig {
    fn from(config: &SyslogConfig) -> Self {
        Self {
            protocol: config.protocol.clone(),
            server: config.server.clone(),
            port: config.port,
            facility: config.facility.clone(),
            hostname: config.hostname.clone(),
            app_name: config.app_name.clone(),
        }
    }
}

/// Syslog 転送サブスクライバー
pub struct SyslogForwarder {
    receiver: broadcast::Receiver<SecurityEvent>,
    config_receiver: watch::Receiver<SyslogRuntimeConfig>,
    runtime: SyslogRuntimeConfig,
}

impl SyslogForwarder {
    /// 設定とイベントバスから SyslogForwarder を構築する
    pub fn new(
        config: &SyslogConfig,
        event_bus: &EventBus,
    ) -> (Self, watch::Sender<SyslogRuntimeConfig>) {
        let runtime = SyslogRuntimeConfig::from(config);
        let (config_sender, config_receiver) = watch::channel(runtime.clone());
        (
            Self {
                receiver: event_bus.subscribe(),
                config_receiver,
                runtime,
            },
            config_sender,
        )
    }

    /// 非同期タスクとして SyslogForwarder を起動する
    pub fn spawn(self) {
        tokio::spawn(async move {
            Self::run_loop(self.receiver, self.config_receiver, self.runtime).await;
        });
    }

    async fn run_loop(
        mut receiver: broadcast::Receiver<SecurityEvent>,
        mut config_receiver: watch::Receiver<SyslogRuntimeConfig>,
        mut runtime: SyslogRuntimeConfig,
    ) {
        let mut transport = Transport::connect(&runtime).await;

        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) => {
                            let message = format_rfc5424(&event, &runtime);
                            if let Err(e) = transport.send(&message, &runtime).await {
                                tracing::warn!(
                                    error = %e,
                                    "Syslog メッセージの送信に失敗しました"
                                );
                                transport = Transport::connect(&runtime).await;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(
                                skipped = n,
                                "Syslog: {} 件のイベントをスキップ（遅延）",
                                n
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::info!("イベントバスが閉じられました。Syslog フォワーダーを終了します");
                            break;
                        }
                    }
                }
                result = config_receiver.changed() => {
                    match result {
                        Ok(()) => {
                            let new_config = config_receiver.borrow_and_update().clone();
                            let needs_reconnect = new_config.protocol != runtime.protocol
                                || new_config.server != runtime.server
                                || new_config.port != runtime.port;
                            runtime = new_config;
                            if needs_reconnect {
                                tracing::info!(
                                    protocol = %runtime.protocol,
                                    server = %runtime.server,
                                    port = runtime.port,
                                    "Syslog: 接続先をリロードしました"
                                );
                                transport = Transport::connect(&runtime).await;
                            } else {
                                tracing::info!("Syslog: 設定をリロードしました");
                            }
                        }
                        Err(_) => {
                            tracing::info!("設定チャネルが閉じられました。Syslog フォワーダーを終了します");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Syslog facility を数値コードに変換する
fn facility_code(facility: &str) -> u8 {
    match facility {
        "kern" => 0,
        "user" => 1,
        "mail" => 2,
        "daemon" => 3,
        "auth" => 4,
        "syslog" => 5,
        "lpr" => 6,
        "news" => 7,
        "uucp" => 8,
        "cron" => 9,
        "authpriv" => 10,
        "ftp" => 11,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        _ => 16, // default to local0
    }
}

/// SecurityEvent の Severity を syslog severity (RFC 5424) に変換する
fn syslog_severity(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 2, // Critical
        Severity::Warning => 4,  // Warning
        Severity::Info => 6,     // Informational
    }
}

/// PRI 値を計算する: facility * 8 + severity
fn pri_value(facility: &str, severity: &Severity) -> u8 {
    facility_code(facility) * 8 + syslog_severity(severity)
}

/// ホスト名を取得する（設定値が空ならシステムから自動取得）
fn resolve_hostname(configured: &str) -> String {
    if configured.is_empty() {
        gethostname::gethostname().to_string_lossy().into_owned()
    } else {
        configured.to_string()
    }
}

/// SystemTime を RFC 3339 形式のタイムスタンプに変換する
fn format_timestamp(ts: SystemTime) -> String {
    match ts.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(dur) => {
            let secs = dur.as_secs();
            let nanos = dur.subsec_nanos();

            let days_since_epoch = secs / 86400;
            let time_of_day = secs % 86400;
            let hours = time_of_day / 3600;
            let minutes = (time_of_day % 3600) / 60;
            let seconds = time_of_day % 60;

            // 年月日を計算
            let (year, month, day) = days_to_ymd(days_since_epoch);

            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
                year,
                month,
                day,
                hours,
                minutes,
                seconds,
                nanos / 1000
            )
        }
        Err(_) => "-".to_string(),
    }
}

/// エポックからの日数を年月日に変換する
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil date from day count algorithm
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// SecurityEvent を RFC 5424 形式のメッセージにフォーマットする
fn format_rfc5424(event: &SecurityEvent, config: &SyslogRuntimeConfig) -> String {
    let pri = pri_value(&config.facility, &event.severity);
    let timestamp = format_timestamp(event.timestamp);
    let hostname = resolve_hostname(&config.hostname);
    let pid = std::process::id();

    // SD-ELEMENT: 構造化データ
    let details_param = match &event.details {
        Some(d) => {
            let escaped = sd_escape(d);
            format!(" details=\"{}\"", escaped)
        }
        None => String::new(),
    };
    let sd = format!(
        "[zettai@0 eventType=\"{}\" sourceModule=\"{}\" severity=\"{}\"{}]",
        sd_escape(&event.event_type),
        sd_escape(&event.source_module),
        event.severity,
        details_param
    );

    format!(
        "<{}>1 {} {} {} {} - {} {}",
        pri, timestamp, hostname, config.app_name, pid, sd, event.message
    )
}

/// SD-PARAM の値をエスケープする（RFC 5424 Section 6.3.3）
fn sd_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(']', "\\]")
}

/// トランスポート層（UDP / TCP）
enum Transport {
    Udp(UdpSocket),
    Tcp(TcpStream),
    Disconnected,
}

impl Transport {
    async fn connect(config: &SyslogRuntimeConfig) -> Self {
        let addr = format!("{}:{}", config.server, config.port);
        match config.protocol.as_str() {
            "udp" => match UdpSocket::bind("0.0.0.0:0").await {
                Ok(socket) => match socket.connect(&addr).await {
                    Ok(()) => {
                        tracing::info!(
                            protocol = "udp",
                            server = %config.server,
                            port = config.port,
                            "Syslog: UDP ソケットを接続しました"
                        );
                        Transport::Udp(socket)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Syslog: UDP 接続に失敗しました");
                        Transport::Disconnected
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "Syslog: UDP ソケットのバインドに失敗しました");
                    Transport::Disconnected
                }
            },
            "tcp" => match TcpStream::connect(&addr).await {
                Ok(stream) => {
                    tracing::info!(
                        protocol = "tcp",
                        server = %config.server,
                        port = config.port,
                        "Syslog: TCP 接続を確立しました"
                    );
                    Transport::Tcp(stream)
                }
                Err(e) => {
                    tracing::warn!(error = %e, addr = %addr, "Syslog: TCP 接続に失敗しました");
                    Transport::Disconnected
                }
            },
            _ => {
                tracing::error!(protocol = %config.protocol, "Syslog: 不明なプロトコル");
                Transport::Disconnected
            }
        }
    }

    async fn send(&mut self, message: &str, config: &SyslogRuntimeConfig) -> Result<(), String> {
        match self {
            Transport::Udp(socket) => {
                socket
                    .send(message.as_bytes())
                    .await
                    .map_err(|e| format!("UDP 送信エラー: {}", e))?;
                Ok(())
            }
            Transport::Tcp(stream) => {
                let framed = format!("{}\n", message);
                stream
                    .write_all(framed.as_bytes())
                    .await
                    .map_err(|e| format!("TCP 送信エラー: {}", e))?;
                Ok(())
            }
            Transport::Disconnected => {
                *self = Self::connect(config).await;
                match self {
                    Transport::Udp(socket) => {
                        socket
                            .send(message.as_bytes())
                            .await
                            .map_err(|e| format!("UDP 送信エラー（再接続後）: {}", e))?;
                        Ok(())
                    }
                    Transport::Tcp(stream) => {
                        let framed = format!("{}\n", message);
                        stream
                            .write_all(framed.as_bytes())
                            .await
                            .map_err(|e| format!("TCP 送信エラー（再接続後）: {}", e))?;
                        Ok(())
                    }
                    Transport::Disconnected => {
                        Err("Syslog サーバへの接続に失敗しました".to_string())
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_facility_code() {
        assert_eq!(facility_code("kern"), 0);
        assert_eq!(facility_code("auth"), 4);
        assert_eq!(facility_code("authpriv"), 10);
        assert_eq!(facility_code("local0"), 16);
        assert_eq!(facility_code("local7"), 23);
        assert_eq!(facility_code("daemon"), 3);
        assert_eq!(facility_code("unknown"), 16);
    }

    #[test]
    fn test_syslog_severity() {
        assert_eq!(syslog_severity(&Severity::Critical), 2);
        assert_eq!(syslog_severity(&Severity::Warning), 4);
        assert_eq!(syslog_severity(&Severity::Info), 6);
    }

    #[test]
    fn test_pri_value() {
        // local0 (16) * 8 + critical (2) = 130
        assert_eq!(pri_value("local0", &Severity::Critical), 130);
        // auth (4) * 8 + warning (4) = 36
        assert_eq!(pri_value("auth", &Severity::Warning), 36);
        // daemon (3) * 8 + info (6) = 30
        assert_eq!(pri_value("daemon", &Severity::Info), 30);
    }

    #[test]
    fn test_sd_escape() {
        assert_eq!(sd_escape("hello"), "hello");
        assert_eq!(sd_escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(sd_escape("a\\b"), "a\\\\b");
        assert_eq!(sd_escape("a]b"), "a\\]b");
    }

    #[test]
    fn test_format_rfc5424_basic() {
        let event = SecurityEvent::new(
            "file_modified",
            Severity::Warning,
            "file_integrity",
            "ファイルが変更されました: /etc/passwd",
        );

        let config = SyslogRuntimeConfig {
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: 514,
            facility: "local0".to_string(),
            hostname: "test-host".to_string(),
            app_name: "zettai-mamorukun".to_string(),
        };

        let msg = format_rfc5424(&event, &config);
        // PRI: local0(16)*8 + warning(4) = 132
        assert!(msg.starts_with("<132>1 "));
        assert!(msg.contains("test-host"));
        assert!(msg.contains("zettai-mamorukun"));
        assert!(msg.contains("eventType=\"file_modified\""));
        assert!(msg.contains("sourceModule=\"file_integrity\""));
        assert!(msg.contains("severity=\"WARNING\""));
        assert!(msg.contains("ファイルが変更されました: /etc/passwd"));
    }

    #[test]
    fn test_format_rfc5424_with_details() {
        let event = SecurityEvent::new(
            "process_anomaly",
            Severity::Critical,
            "process_monitor",
            "不審なプロセス検知",
        )
        .with_details("pid=1234, name=suspicious");

        let config = SyslogRuntimeConfig {
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: 514,
            facility: "auth".to_string(),
            hostname: "prod-server".to_string(),
            app_name: "zettai-mamorukun".to_string(),
        };

        let msg = format_rfc5424(&event, &config);
        // PRI: auth(4)*8 + critical(2) = 34
        assert!(msg.starts_with("<34>1 "));
        assert!(msg.contains("details=\"pid=1234, name=suspicious\""));
    }

    #[test]
    fn test_format_rfc5424_sd_escape_in_values() {
        let event = SecurityEvent::new("test\"event", Severity::Info, "test]module", "メッセージ");

        let config = SyslogRuntimeConfig {
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: 514,
            facility: "local0".to_string(),
            hostname: "host".to_string(),
            app_name: "app".to_string(),
        };

        let msg = format_rfc5424(&event, &config);
        assert!(msg.contains(r#"eventType="test\"event""#));
        assert!(msg.contains(r#"sourceModule="test\]module""#));
    }

    #[test]
    fn test_format_timestamp() {
        let ts = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1700000000);
        let formatted = format_timestamp(ts);
        assert!(formatted.starts_with("2023-11-14T"));
        assert!(formatted.ends_with('Z'));
    }

    #[test]
    fn test_days_to_ymd() {
        // 1970-01-01
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        // 2000-01-01 = day 10957
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
    }

    #[test]
    fn test_resolve_hostname_configured() {
        assert_eq!(resolve_hostname("my-host"), "my-host");
    }

    #[test]
    fn test_resolve_hostname_auto() {
        let hostname = resolve_hostname("");
        assert!(!hostname.is_empty());
    }

    #[test]
    fn test_syslog_runtime_config_from_syslog_config() {
        let config = SyslogConfig {
            enabled: true,
            protocol: "tcp".to_string(),
            server: "192.168.1.100".to_string(),
            port: 1514,
            facility: "auth".to_string(),
            hostname: "my-server".to_string(),
            app_name: "test-app".to_string(),
        };
        let runtime = SyslogRuntimeConfig::from(&config);
        assert_eq!(runtime.protocol, "tcp");
        assert_eq!(runtime.server, "192.168.1.100");
        assert_eq!(runtime.port, 1514);
        assert_eq!(runtime.facility, "auth");
        assert_eq!(runtime.hostname, "my-server");
        assert_eq!(runtime.app_name, "test-app");
    }

    #[test]
    fn test_syslog_forwarder_new() {
        let config = SyslogConfig::default();
        let bus = EventBus::new(16);
        let (forwarder, _sender) = SyslogForwarder::new(&config, &bus);
        assert_eq!(forwarder.runtime.protocol, "udp");
        assert_eq!(forwarder.runtime.server, "127.0.0.1");
        assert_eq!(forwarder.runtime.port, 514);
    }

    #[tokio::test]
    async fn test_syslog_forwarder_config_channel_closed() {
        let config = SyslogConfig {
            enabled: true,
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: 19514,
            facility: "local0".to_string(),
            hostname: "test".to_string(),
            app_name: "test".to_string(),
        };
        let bus = EventBus::new(16);
        let (forwarder, sender) = SyslogForwarder::new(&config, &bus);
        forwarder.spawn();

        // sender をドロップしてチャネルを閉じる
        drop(sender);

        // フォワーダーが正常に終了することを確認
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn test_syslog_forwarder_receives_and_sends_udp() {
        // ローカル UDP サーバを起動
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let config = SyslogConfig {
            enabled: true,
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: server_addr.port(),
            facility: "local0".to_string(),
            hostname: "test-host".to_string(),
            app_name: "zettai-test".to_string(),
        };
        let bus = EventBus::new(16);
        let (forwarder, _sender) = SyslogForwarder::new(&config, &bus);
        forwarder.spawn();

        // イベントを発行
        bus.publish(SecurityEvent::new(
            "test_event",
            Severity::Warning,
            "test_module",
            "テストメッセージ",
        ));

        // メッセージの受信を待つ
        let mut buf = [0u8; 4096];
        let timeout = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server_socket.recv(&mut buf),
        )
        .await;

        match timeout {
            Ok(Ok(len)) => {
                let received = std::str::from_utf8(&buf[..len]).unwrap();
                assert!(received.contains("<132>1 "));
                assert!(received.contains("test-host"));
                assert!(received.contains("zettai-test"));
                assert!(received.contains("eventType=\"test_event\""));
                assert!(received.contains("テストメッセージ"));
            }
            _ => panic!("UDP メッセージを受信できませんでした"),
        }
    }

    #[tokio::test]
    async fn test_syslog_forwarder_receives_and_sends_tcp() {
        // ローカル TCP サーバを起動
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let config = SyslogConfig {
            enabled: true,
            protocol: "tcp".to_string(),
            server: "127.0.0.1".to_string(),
            port: server_addr.port(),
            facility: "auth".to_string(),
            hostname: "tcp-test".to_string(),
            app_name: "zettai-tcp".to_string(),
        };
        let bus = EventBus::new(16);
        let (forwarder, _sender) = SyslogForwarder::new(&config, &bus);
        forwarder.spawn();

        // TCP 接続が確立されるのを待つ
        let (mut stream, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
                .await
                .unwrap()
                .unwrap();

        // イベントを発行
        bus.publish(SecurityEvent::new(
            "tcp_test_event",
            Severity::Critical,
            "tcp_module",
            "TCP テストメッセージ",
        ));

        // メッセージの受信を待つ
        let mut buf = [0u8; 4096];
        let timeout = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
        )
        .await;

        match timeout {
            Ok(Ok(len)) => {
                let received = std::str::from_utf8(&buf[..len]).unwrap();
                // PRI: auth(4)*8 + critical(2) = 34
                assert!(received.contains("<34>1 "));
                assert!(received.contains("tcp-test"));
                assert!(received.contains("zettai-tcp"));
                assert!(received.contains("TCP テストメッセージ"));
                assert!(received.ends_with('\n'));
            }
            _ => panic!("TCP メッセージを受信できませんでした"),
        }
    }

    #[tokio::test]
    async fn test_syslog_forwarder_hot_reload() {
        // ローカル UDP サーバを起動
        let server1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr1 = server1.local_addr().unwrap();

        let config = SyslogConfig {
            enabled: true,
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: addr1.port(),
            facility: "local0".to_string(),
            hostname: "reload-test".to_string(),
            app_name: "zettai-reload".to_string(),
        };
        let bus = EventBus::new(16);
        let (forwarder, sender) = SyslogForwarder::new(&config, &bus);
        forwarder.spawn();

        // facility のみ変更（再接続不要）
        let new_runtime = SyslogRuntimeConfig {
            protocol: "udp".to_string(),
            server: "127.0.0.1".to_string(),
            port: addr1.port(),
            facility: "auth".to_string(),
            hostname: "reload-test".to_string(),
            app_name: "zettai-reload".to_string(),
        };
        sender.send(new_runtime).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 新しい facility でイベント送信
        bus.publish(SecurityEvent::new(
            "reload_test",
            Severity::Info,
            "test",
            "リロードテスト",
        ));

        let mut buf = [0u8; 4096];
        let timeout =
            tokio::time::timeout(std::time::Duration::from_secs(2), server1.recv(&mut buf)).await;

        match timeout {
            Ok(Ok(len)) => {
                let received = std::str::from_utf8(&buf[..len]).unwrap();
                // PRI: auth(4)*8 + info(6) = 38
                assert!(received.starts_with("<38>1 "));
            }
            _ => panic!("リロード後の UDP メッセージを受信できませんでした"),
        }
    }
}
