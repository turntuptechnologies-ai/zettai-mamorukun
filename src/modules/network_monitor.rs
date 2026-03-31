//! ネットワーク接続監視モジュール
//!
//! `/proc/net/tcp` と `/proc/net/udp` を定期的に読み取り、不審な接続を検知する。
//!
//! 検知対象:
//! - 不審なポートへの接続（C2 サーバ等で使われるポート）
//! - 接続数の異常な増加（DDoS やワームの兆候）

use crate::config::NetworkMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::Module;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use tokio_util::sync::CancellationToken;

/// プロトコル種別
#[derive(Debug, Clone, PartialEq, Eq)]
enum Protocol {
    Tcp,
    Udp,
}

/// パースされた接続エントリ
#[derive(Debug, Clone)]
struct ConnectionEntry {
    protocol: Protocol,
    local_addr: Ipv4Addr,
    local_port: u16,
    remote_addr: Ipv4Addr,
    remote_port: u16,
    state: u8,
}

/// `/proc/net/tcp` または `/proc/net/udp` の内容をパースする
fn parse_proc_net(content: &str, protocol: Protocol) -> Vec<ConnectionEntry> {
    let mut entries = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            tracing::debug!(line = line, "フィールド数が不足しているためスキップします");
            continue;
        }

        let local = fields[1];
        let remote = fields[2];
        let state_str = fields[3];

        let Some((local_addr, local_port)) = parse_addr_port(local) else {
            tracing::debug!(field = local, "ローカルアドレスのパースに失敗しました");
            continue;
        };

        let Some((remote_addr, remote_port)) = parse_addr_port(remote) else {
            tracing::debug!(field = remote, "リモートアドレスのパースに失敗しました");
            continue;
        };

        let Ok(state) = u8::from_str_radix(state_str, 16) else {
            tracing::debug!(field = state_str, "ステートのパースに失敗しました");
            continue;
        };

        entries.push(ConnectionEntry {
            protocol: protocol.clone(),
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
        });
    }

    entries
}

/// `AABBCCDD:PORT` 形式のアドレスをパースする
///
/// `/proc/net/tcp` は IP アドレスをホストバイトオーダーの 16 進数で格納するため、
/// `to_ne_bytes` でバイト列に変換して `Ipv4Addr` を構築する。
fn parse_addr_port(field: &str) -> Option<(Ipv4Addr, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let raw = u32::from_str_radix(addr_hex, 16).ok()?;
    let addr = Ipv4Addr::from(raw.to_ne_bytes());
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((addr, port))
}

/// 不審なポートへの接続を検知する
///
/// TCP ESTABLISHED (state==0x01) で remote_port が suspicious_ports に含まれる接続、
/// または remote_addr が 0.0.0.0 でない UDP 接続を返す。
fn detect_suspicious_port_connections(
    entries: &[ConnectionEntry],
    suspicious_ports: &HashSet<u16>,
) -> Vec<ConnectionEntry> {
    entries
        .iter()
        .filter(|e| match e.protocol {
            Protocol::Tcp => e.state == 0x01 && suspicious_ports.contains(&e.remote_port),
            Protocol::Udp => {
                e.remote_addr != Ipv4Addr::new(0, 0, 0, 0)
                    && suspicious_ports.contains(&e.remote_port)
            }
        })
        .cloned()
        .collect()
}

/// 接続数が閾値を超過しているか検知する
///
/// ESTABLISHED TCP 接続とアクティブ UDP 接続（remote_addr が 0.0.0.0 でない）の
/// 合計が max_connections を超過している場合、その接続数を返す。
fn detect_connection_count_exceeded(
    entries: &[ConnectionEntry],
    max_connections: u32,
) -> Option<u32> {
    let count = entries
        .iter()
        .filter(|e| match e.protocol {
            Protocol::Tcp => e.state == 0x01,
            Protocol::Udp => e.remote_addr != Ipv4Addr::new(0, 0, 0, 0),
        })
        .count() as u32;

    if count > max_connections {
        Some(count)
    } else {
        None
    }
}

/// プライベート IP アドレスかどうかを判定する
fn is_private_addr(addr: &Ipv4Addr) -> bool {
    let octets = addr.octets();
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 127.0.0.0/8
    if octets[0] == 127 {
        return true;
    }
    // 0.0.0.0
    *addr == Ipv4Addr::new(0, 0, 0, 0)
}

/// ネットワーク接続監視モジュール
///
/// `/proc/net/tcp` と `/proc/net/udp` を定期的にスキャンし、
/// 不審な接続を検知してイベントを発行する。
pub struct NetworkMonitorModule {
    config: NetworkMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl NetworkMonitorModule {
    /// 新しいネットワーク接続監視モジュールを作成する
    pub fn new(config: NetworkMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// `/proc/net/tcp` と `/proc/net/udp` を読み取り、接続エントリを返す
    fn read_connections() -> Vec<ConnectionEntry> {
        let mut entries = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            entries.extend(parse_proc_net(&content, Protocol::Tcp));
        } else {
            tracing::warn!("/proc/net/tcp の読み取りに失敗しました");
        }

        if let Ok(content) = std::fs::read_to_string("/proc/net/udp") {
            entries.extend(parse_proc_net(&content, Protocol::Udp));
        } else {
            tracing::warn!("/proc/net/udp の読み取りに失敗しました");
        }

        entries
    }
}

impl Module for NetworkMonitorModule {
    fn name(&self) -> &str {
        "network_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        if self.config.suspicious_ports.is_empty() {
            tracing::warn!("suspicious_ports が空です。不審ポート検知は行われません");
        }

        tracing::info!(
            interval_secs = self.config.interval_secs,
            suspicious_ports = ?self.config.suspicious_ports,
            max_connections = self.config.max_connections,
            "ネットワーク接続監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<(), AppError> {
        // 初回スキャンで動作確認
        let connections = Self::read_connections();
        tracing::info!(
            connection_count = connections.len(),
            "初回ネットワーク接続スキャンが完了しました"
        );

        let suspicious_ports: HashSet<u16> = self.config.suspicious_ports.iter().copied().collect();
        let max_connections = self.config.max_connections;
        let interval_secs = self.config.interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        // 既知の不審接続を記録し、同じ接続の繰り返し警告を抑制
        let mut known_suspicious: HashSet<(Ipv4Addr, u16)> = HashSet::new();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ネットワーク接続監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let entries = NetworkMonitorModule::read_connections();

                        // 不審ポート接続の検知
                        let suspicious =
                            detect_suspicious_port_connections(&entries, &suspicious_ports);

                        // 現在の不審接続セットを構築
                        let current_keys: HashSet<(Ipv4Addr, u16)> = suspicious
                            .iter()
                            .map(|e| (e.remote_addr, e.remote_port))
                            .collect();

                        // 消えた接続を known から除去
                        known_suspicious.retain(|key| current_keys.contains(key));

                        for entry in &suspicious {
                            let key = (entry.remote_addr, entry.remote_port);
                            if known_suspicious.insert(key) {
                                let proto = match entry.protocol {
                                    Protocol::Tcp => "TCP",
                                    Protocol::Udp => "UDP",
                                };
                                let is_private = is_private_addr(&entry.remote_addr);
                                tracing::warn!(
                                    protocol = proto,
                                    local = %format!("{}:{}", entry.local_addr, entry.local_port),
                                    remote = %format!("{}:{}", entry.remote_addr, entry.remote_port),
                                    private = is_private,
                                    "不審なポートへの接続を検知しました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "suspicious_port_connection",
                                            Severity::Warning,
                                            "network_monitor",
                                            format!(
                                                "不審なポートへの接続を検知しました: {} {}:{} -> {}:{}",
                                                proto,
                                                entry.local_addr,
                                                entry.local_port,
                                                entry.remote_addr,
                                                entry.remote_port,
                                            ),
                                        )
                                        .with_details(format!(
                                            "protocol={}, local={}:{}, remote={}:{}, private={}",
                                            proto,
                                            entry.local_addr,
                                            entry.local_port,
                                            entry.remote_addr,
                                            entry.remote_port,
                                            is_private,
                                        )),
                                    );
                                }
                            }
                        }

                        // 接続数超過の検知
                        if let Some(count) =
                            detect_connection_count_exceeded(&entries, max_connections)
                        {
                            tracing::warn!(
                                count = count,
                                max = max_connections,
                                "接続数が閾値を超過しています"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "connection_count_exceeded",
                                        Severity::Warning,
                                        "network_monitor",
                                        format!(
                                            "接続数が閾値を超過しています: {} (閾値: {})",
                                            count, max_connections,
                                        ),
                                    )
                                    .with_details(format!(
                                        "count={}, max_connections={}",
                                        count, max_connections,
                                    )),
                                );
                            }
                        }

                        if suspicious.is_empty() {
                            tracing::debug!("不審なネットワーク接続は検知されませんでした");
                        }
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

    #[test]
    fn test_parse_proc_net_tcp() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0CEA 0100A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0"#;

        let entries = parse_proc_net(content, Protocol::Tcp);
        assert_eq!(entries.len(), 2);

        // 最初のエントリ: 127.0.0.1:53 -> 0.0.0.0:0, state=0x0A (LISTEN)
        assert_eq!(entries[0].protocol, Protocol::Tcp);
        assert_eq!(entries[0].local_addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(entries[0].local_port, 53);
        assert_eq!(entries[0].remote_addr, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(entries[0].remote_port, 0);
        assert_eq!(entries[0].state, 0x0A);

        // 2番目のエントリ: 127.0.0.1:3306 -> 192.168.0.1:443, state=0x01 (ESTABLISHED)
        assert_eq!(entries[1].protocol, Protocol::Tcp);
        assert_eq!(entries[1].local_addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(entries[1].local_port, 3306);
        assert_eq!(entries[1].remote_addr, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(entries[1].remote_port, 443);
        assert_eq!(entries[1].state, 0x01);
    }

    #[test]
    fn test_parse_proc_net_udp() {
        let content = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"#;

        let entries = parse_proc_net(content, Protocol::Udp);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol, Protocol::Udp);
        assert_eq!(entries[0].local_addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(entries[0].local_port, 53);
        assert_eq!(entries[0].state, 0x07);
    }

    #[test]
    fn test_parse_proc_net_invalid_lines() {
        let content = r#"  sl  local_address rem_address   st
   invalid line
   short"#;

        let entries = parse_proc_net(content, Protocol::Tcp);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_proc_net_empty() {
        let entries = parse_proc_net("", Protocol::Tcp);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_proc_net_header_only() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        let entries = parse_proc_net(content, Protocol::Tcp);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_detect_suspicious_port_connections_tcp() {
        let suspicious_ports: HashSet<u16> = [4444, 5555].into_iter().collect();

        let entries = vec![
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: Ipv4Addr::new(192, 168, 1, 100),
                local_port: 54321,
                remote_addr: Ipv4Addr::new(10, 0, 0, 1),
                remote_port: 4444,
                state: 0x01, // ESTABLISHED
            },
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: Ipv4Addr::new(192, 168, 1, 100),
                local_port: 54322,
                remote_addr: Ipv4Addr::new(10, 0, 0, 2),
                remote_port: 80,
                state: 0x01, // ESTABLISHED
            },
        ];

        let result = detect_suspicious_port_connections(&entries, &suspicious_ports);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].remote_port, 4444);
    }

    #[test]
    fn test_detect_suspicious_port_connections_tcp_not_established() {
        let suspicious_ports: HashSet<u16> = [4444].into_iter().collect();

        let entries = vec![ConnectionEntry {
            protocol: Protocol::Tcp,
            local_addr: Ipv4Addr::new(192, 168, 1, 100),
            local_port: 54321,
            remote_addr: Ipv4Addr::new(10, 0, 0, 1),
            remote_port: 4444,
            state: 0x0A, // LISTEN - not ESTABLISHED
        }];

        let result = detect_suspicious_port_connections(&entries, &suspicious_ports);
        assert!(result.is_empty());
    }

    #[test]
    fn test_detect_suspicious_port_connections_normal_ports() {
        let suspicious_ports: HashSet<u16> = [4444, 5555].into_iter().collect();

        let entries = vec![
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: Ipv4Addr::new(192, 168, 1, 100),
                local_port: 54321,
                remote_addr: Ipv4Addr::new(10, 0, 0, 1),
                remote_port: 443,
                state: 0x01,
            },
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: Ipv4Addr::new(192, 168, 1, 100),
                local_port: 54322,
                remote_addr: Ipv4Addr::new(10, 0, 0, 2),
                remote_port: 80,
                state: 0x01,
            },
        ];

        let result = detect_suspicious_port_connections(&entries, &suspicious_ports);
        assert!(result.is_empty());
    }

    #[test]
    fn test_detect_suspicious_port_connections_udp() {
        let suspicious_ports: HashSet<u16> = [6666].into_iter().collect();

        let entries = vec![
            ConnectionEntry {
                protocol: Protocol::Udp,
                local_addr: Ipv4Addr::new(192, 168, 1, 100),
                local_port: 54321,
                remote_addr: Ipv4Addr::new(10, 0, 0, 1),
                remote_port: 6666,
                state: 0x07,
            },
            // remote_addr が 0.0.0.0 の UDP は除外
            ConnectionEntry {
                protocol: Protocol::Udp,
                local_addr: Ipv4Addr::new(192, 168, 1, 100),
                local_port: 53,
                remote_addr: Ipv4Addr::new(0, 0, 0, 0),
                remote_port: 6666,
                state: 0x07,
            },
        ];

        let result = detect_suspicious_port_connections(&entries, &suspicious_ports);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].remote_addr, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_detect_connection_count_exceeded() {
        let entries: Vec<ConnectionEntry> = (0..10)
            .map(|i| ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: Ipv4Addr::new(192, 168, 1, 100),
                local_port: 50000 + i,
                remote_addr: Ipv4Addr::new(10, 0, 0, 1),
                remote_port: 80,
                state: 0x01, // ESTABLISHED
            })
            .collect();

        // 閾値 5 → 10 接続で超過
        assert_eq!(detect_connection_count_exceeded(&entries, 5), Some(10));
    }

    #[test]
    fn test_detect_connection_count_not_exceeded() {
        let entries: Vec<ConnectionEntry> = (0..5)
            .map(|i| ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: Ipv4Addr::new(192, 168, 1, 100),
                local_port: 50000 + i,
                remote_addr: Ipv4Addr::new(10, 0, 0, 1),
                remote_port: 80,
                state: 0x01,
            })
            .collect();

        // 閾値 5 → 5 接続で超過なし（> であり >= ではない）
        assert_eq!(detect_connection_count_exceeded(&entries, 5), None);
    }

    #[test]
    fn test_detect_connection_count_excludes_listen() {
        let entries = vec![
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: Ipv4Addr::new(192, 168, 1, 100),
                local_port: 80,
                remote_addr: Ipv4Addr::new(0, 0, 0, 0),
                remote_port: 0,
                state: 0x0A, // LISTEN
            },
            ConnectionEntry {
                protocol: Protocol::Tcp,
                local_addr: Ipv4Addr::new(192, 168, 1, 100),
                local_port: 50000,
                remote_addr: Ipv4Addr::new(10, 0, 0, 1),
                remote_port: 80,
                state: 0x01, // ESTABLISHED
            },
        ];

        // LISTEN は数えないので 1 接続のみ
        assert_eq!(detect_connection_count_exceeded(&entries, 0), Some(1));
        assert_eq!(detect_connection_count_exceeded(&entries, 1), None);
    }

    #[test]
    fn test_is_private_addr_10() {
        assert!(is_private_addr(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_addr(&Ipv4Addr::new(10, 255, 255, 255)));
    }

    #[test]
    fn test_is_private_addr_172() {
        assert!(is_private_addr(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_addr(&Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_private_addr(&Ipv4Addr::new(172, 15, 0, 1)));
        assert!(!is_private_addr(&Ipv4Addr::new(172, 32, 0, 1)));
    }

    #[test]
    fn test_is_private_addr_192_168() {
        assert!(is_private_addr(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_private_addr(&Ipv4Addr::new(192, 168, 255, 255)));
        assert!(!is_private_addr(&Ipv4Addr::new(192, 169, 0, 1)));
    }

    #[test]
    fn test_is_private_addr_127() {
        assert!(is_private_addr(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_addr(&Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn test_is_private_addr_zero() {
        assert!(is_private_addr(&Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn test_is_private_addr_public() {
        assert!(!is_private_addr(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_addr(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_addr(&Ipv4Addr::new(203, 0, 113, 1)));
    }

    #[test]
    fn test_parse_addr_port() {
        // 0100007F:0035 → 127.0.0.1:53
        let result = parse_addr_port("0100007F:0035");
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(port, 53);
    }

    #[test]
    fn test_parse_addr_port_invalid() {
        assert!(parse_addr_port("invalid").is_none());
        assert!(parse_addr_port("GGGGGGGG:0035").is_none());
        assert!(parse_addr_port("0100007F:GGGG").is_none());
    }

    #[test]
    fn test_init_zero_interval() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 0,
            suspicious_ports: vec![4444],
            max_connections: 1000,
        };
        let mut module = NetworkMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid_config() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 30,
            suspicious_ports: vec![4444, 5555],
            max_connections: 1000,
        };
        let mut module = NetworkMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_empty_suspicious_ports() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 30,
            suspicious_ports: vec![],
            max_connections: 1000,
        };
        let mut module = NetworkMonitorModule::new(config, None);
        // 空でもエラーにはならない（warn のみ）
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 3600,
            suspicious_ports: vec![4444],
            max_connections: 1000,
        };
        let mut module = NetworkMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[test]
    fn test_init_with_event_bus_none() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 30,
            suspicious_ports: vec![4444],
            max_connections: 1000,
        };
        let mut module = NetworkMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_with_event_bus_some() {
        let config = NetworkMonitorConfig {
            enabled: true,
            interval_secs: 30,
            suspicious_ports: vec![4444],
            max_connections: 1000,
        };
        let bus = EventBus::new(16);
        let mut module = NetworkMonitorModule::new(config, Some(bus));
        assert!(module.init().is_ok());
    }
}
