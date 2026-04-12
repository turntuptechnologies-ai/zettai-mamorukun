//! ネットワーク名前解決監視モジュール
//!
//! `/proc/net/udp` と `/proc/net/udp6` から DNS ポート（53）宛の接続を定期スキャンし、
//! 不審な DNS アクティビティを検知する。
//!
//! 検知対象:
//! - DNS ポート宛接続数の異常増加（高頻度クエリ）
//! - `/etc/resolv.conf` に設定されていない不明 DNS サーバへの接続
//! - `tx_queue` の異常値（DNS トンネリング兆候）

use crate::config::DnsQueryMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio_util::sync::CancellationToken;

/// DNS ポート番号
const DNS_PORT: u16 = 53;

/// `/proc/net/udp` のパース済みエントリ
#[derive(Debug, Clone)]
struct UdpEntry {
    #[allow(dead_code)]
    local_addr: IpAddr,
    #[allow(dead_code)]
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    tx_queue: u64,
    #[allow(dead_code)]
    rx_queue: u64,
}

/// `/proc/net/udp` の内容をパースする
fn parse_proc_net_udp(content: &str, is_v6: bool) -> Vec<UdpEntry> {
    let mut entries = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }

        let local = fields[1];
        let remote = fields[2];
        // fields[4] は "tx_queue:rx_queue" 形式
        let queue_field = fields[4];

        let (local_addr, local_port) = if is_v6 {
            let Some((addr, port)) = parse_addr_port_v6(local) else {
                continue;
            };
            (IpAddr::V6(addr), port)
        } else {
            let Some((addr, port)) = parse_addr_port_v4(local) else {
                continue;
            };
            (IpAddr::V4(addr), port)
        };

        let (remote_addr, remote_port) = if is_v6 {
            let Some((addr, port)) = parse_addr_port_v6(remote) else {
                continue;
            };
            (IpAddr::V6(addr), port)
        } else {
            let Some((addr, port)) = parse_addr_port_v4(remote) else {
                continue;
            };
            (IpAddr::V4(addr), port)
        };

        let (tx_queue, rx_queue) = parse_queue(queue_field).unwrap_or((0, 0));

        entries.push(UdpEntry {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            tx_queue,
            rx_queue,
        });
    }

    entries
}

/// `AABBCCDD:PORT` 形式の IPv4 アドレスをパースする
fn parse_addr_port_v4(field: &str) -> Option<(Ipv4Addr, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let raw = u32::from_str_radix(addr_hex, 16).ok()?;
    let addr = Ipv4Addr::from(raw.to_ne_bytes());
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((addr, port))
}

/// `/proc/net/udp6` 形式の IPv6 アドレスをパースする
fn parse_addr_port_v6(field: &str) -> Option<(Ipv6Addr, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    if addr_hex.len() != 32 {
        return None;
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    let mut octets = [0u8; 16];
    for i in 0..4 {
        let word_hex = &addr_hex[i * 8..(i + 1) * 8];
        let word = u32::from_str_radix(word_hex, 16).ok()?;
        let bytes = word.to_ne_bytes();
        octets[i * 4] = bytes[0];
        octets[i * 4 + 1] = bytes[1];
        octets[i * 4 + 2] = bytes[2];
        octets[i * 4 + 3] = bytes[3];
    }

    Some((Ipv6Addr::from(octets), port))
}

/// `tx_queue:rx_queue` 形式の文字列をパースする
fn parse_queue(field: &str) -> Option<(u64, u64)> {
    let (tx_hex, rx_hex) = field.split_once(':')?;
    let tx = u64::from_str_radix(tx_hex, 16).ok()?;
    let rx = u64::from_str_radix(rx_hex, 16).ok()?;
    Some((tx, rx))
}

/// `/etc/resolv.conf` から nameserver アドレスを抽出する
fn parse_resolv_conf(content: &str) -> HashSet<IpAddr> {
    let mut servers = HashSet::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(addr_str) = line.strip_prefix("nameserver") {
            let addr_str = addr_str.trim();
            if let Ok(addr) = addr_str.parse::<IpAddr>() {
                servers.insert(addr);
            }
        }
    }
    servers
}

/// DNS ポート宛の UDP エントリのみをフィルタする
fn filter_dns_entries(entries: &[UdpEntry]) -> Vec<&UdpEntry> {
    entries
        .iter()
        .filter(|e| e.remote_port == DNS_PORT && !is_unspecified(&e.remote_addr))
        .collect()
}

/// アドレスが未指定（0.0.0.0 または ::）かどうかを判定する
fn is_unspecified(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => *v4 == Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

/// ネットワーク名前解決監視モジュール
///
/// `/proc/net/udp` と `/proc/net/udp6` を定期スキャンし、DNS ポート（53）宛の
/// 接続を監視して不審なアクティビティを検知する。
pub struct DnsQueryMonitorModule {
    config: DnsQueryMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl DnsQueryMonitorModule {
    /// 新しいネットワーク名前解決監視モジュールを作成する
    pub fn new(config: DnsQueryMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// `/proc/net/udp` と `/proc/net/udp6` から UDP エントリを読み取る
    fn read_udp_entries() -> Vec<UdpEntry> {
        let mut entries = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/proc/net/udp") {
            entries.extend(parse_proc_net_udp(&content, false));
        } else {
            tracing::debug!("/proc/net/udp の読み取りに失敗しました");
        }

        if let Ok(content) = std::fs::read_to_string("/proc/net/udp6") {
            entries.extend(parse_proc_net_udp(&content, true));
        } else {
            tracing::debug!("/proc/net/udp6 の読み取りに失敗しました");
        }

        entries
    }

    /// `/etc/resolv.conf` から正規の DNS サーバアドレスを読み取る
    fn read_known_dns_servers() -> HashSet<IpAddr> {
        match std::fs::read_to_string("/etc/resolv.conf") {
            Ok(content) => parse_resolv_conf(&content),
            Err(e) => {
                tracing::warn!(error = %e, "/etc/resolv.conf の読み取りに失敗しました");
                HashSet::new()
            }
        }
    }

    /// DNS 接続数の異常検知
    fn check_high_query_rate(dns_entries: &[&UdpEntry], threshold: u64) -> Option<u64> {
        let count = dns_entries.len() as u64;
        if count >= threshold {
            Some(count)
        } else {
            None
        }
    }

    /// 不明 DNS サーバの検知
    fn check_unknown_dns_servers(
        dns_entries: &[&UdpEntry],
        known_servers: &HashSet<IpAddr>,
        whitelist: &HashSet<IpAddr>,
    ) -> Vec<IpAddr> {
        let mut unknown: Vec<IpAddr> = Vec::new();
        let mut seen = HashSet::new();

        for entry in dns_entries {
            let addr = entry.remote_addr;
            if !known_servers.contains(&addr) && !whitelist.contains(&addr) && seen.insert(addr) {
                unknown.push(addr);
            }
        }

        unknown
    }

    /// DNS トンネリング兆候の検知（tx_queue 異常値）
    fn check_tunnel_suspected(dns_entries: &[&UdpEntry], tx_threshold: u64) -> Vec<(IpAddr, u64)> {
        let mut suspected: Vec<(IpAddr, u64)> = Vec::new();
        let mut seen = HashSet::new();

        for entry in dns_entries {
            if entry.tx_queue >= tx_threshold && seen.insert(entry.remote_addr) {
                suspected.push((entry.remote_addr, entry.tx_queue));
            }
        }

        suspected
    }
}

impl Module for DnsQueryMonitorModule {
    fn name(&self) -> &str {
        "dns_query_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            query_rate_threshold = self.config.query_rate_threshold,
            unknown_dns_server_detection = self.config.unknown_dns_server_detection,
            tx_queue_threshold = self.config.tx_queue_threshold,
            "ネットワーク名前解決監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        // 初回スキャンで動作確認
        let entries = Self::read_udp_entries();
        let dns_entries = filter_dns_entries(&entries);
        tracing::info!(
            udp_entry_count = entries.len(),
            dns_entry_count = dns_entries.len(),
            "初回 DNS 接続スキャンが完了しました"
        );

        let scan_interval_secs = self.config.scan_interval_secs;
        let query_rate_threshold = self.config.query_rate_threshold;
        let unknown_dns_detection = self.config.unknown_dns_server_detection;
        let tx_queue_threshold = self.config.tx_queue_threshold;
        let whitelist: HashSet<IpAddr> = self
            .config
            .whitelist_addresses
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            // 既報告の不明 DNS サーバを記録し、重複アラートを抑制
            let mut known_unknown_servers: HashSet<IpAddr> = HashSet::new();

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ネットワーク名前解決監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let entries = DnsQueryMonitorModule::read_udp_entries();
                        let dns_entries = filter_dns_entries(&entries);

                        // 1. DNS 接続数の異常検知
                        if let Some(count) = DnsQueryMonitorModule::check_high_query_rate(
                            &dns_entries,
                            query_rate_threshold,
                        ) {
                            tracing::warn!(
                                count = count,
                                threshold = query_rate_threshold,
                                "DNS 接続数が閾値を超過しています"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "dns_high_query_rate",
                                        Severity::Warning,
                                        "dns_query_monitor",
                                        format!(
                                            "DNS 接続数が閾値を超過しています: {} (閾値: {})",
                                            count, query_rate_threshold
                                        ),
                                    )
                                    .with_details(format!(
                                        "count={}, threshold={}",
                                        count, query_rate_threshold
                                    )),
                                );
                            }
                        }

                        // 2. 不明 DNS サーバの検知
                        if unknown_dns_detection {
                            let known_servers = DnsQueryMonitorModule::read_known_dns_servers();
                            let unknown = DnsQueryMonitorModule::check_unknown_dns_servers(
                                &dns_entries,
                                &known_servers,
                                &whitelist,
                            );

                            // 消えた不明サーバを known_unknown から除去
                            let current_unknown: HashSet<IpAddr> =
                                unknown.iter().copied().collect();
                            known_unknown_servers
                                .retain(|addr| current_unknown.contains(addr));

                            for addr in &unknown {
                                if known_unknown_servers.insert(*addr) {
                                    tracing::warn!(
                                        server = %addr,
                                        "resolv.conf に未登録の DNS サーバへの接続を検知しました"
                                    );
                                    if let Some(ref bus) = event_bus {
                                        bus.publish(
                                            SecurityEvent::new(
                                                "dns_unknown_server",
                                                Severity::Warning,
                                                "dns_query_monitor",
                                                format!(
                                                    "resolv.conf に未登録の DNS サーバへの接続を検知しました: {}",
                                                    addr
                                                ),
                                            )
                                            .with_details(format!("server={}", addr)),
                                        );
                                    }
                                }
                            }
                        }

                        // 3. DNS トンネリング兆候の検知
                        let suspected = DnsQueryMonitorModule::check_tunnel_suspected(
                            &dns_entries,
                            tx_queue_threshold,
                        );
                        for (addr, tx_queue) in &suspected {
                            tracing::warn!(
                                server = %addr,
                                tx_queue = tx_queue,
                                threshold = tx_queue_threshold,
                                "DNS トンネリングの兆候を検知しました（tx_queue 異常値）"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "dns_tunnel_suspected",
                                        Severity::Critical,
                                        "dns_query_monitor",
                                        format!(
                                            "DNS トンネリングの兆候を検知しました: server={}, tx_queue={} (閾値: {})",
                                            addr, tx_queue, tx_queue_threshold
                                        ),
                                    )
                                    .with_details(format!(
                                        "server={}, tx_queue={}, threshold={}",
                                        addr, tx_queue, tx_queue_threshold
                                    )),
                                );
                            }
                        }

                        if dns_entries.is_empty() {
                            tracing::debug!("DNS ポート宛の UDP 接続はありません");
                        }
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

        let entries = Self::read_udp_entries();
        let dns_entries = filter_dns_entries(&entries);
        let items_scanned = dns_entries.len();

        let mut issues_found = 0;

        // 高頻度クエリチェック
        if Self::check_high_query_rate(&dns_entries, self.config.query_rate_threshold).is_some() {
            issues_found += 1;
        }

        // 不明 DNS サーバチェック
        if self.config.unknown_dns_server_detection {
            let known_servers = Self::read_known_dns_servers();
            let whitelist: HashSet<IpAddr> = self
                .config
                .whitelist_addresses
                .iter()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .collect();
            let unknown = Self::check_unknown_dns_servers(&dns_entries, &known_servers, &whitelist);
            issues_found += unknown.len();
        }

        // トンネリングチェック
        let suspected = Self::check_tunnel_suspected(&dns_entries, self.config.tx_queue_threshold);
        issues_found += suspected.len();

        let duration = start.elapsed();

        let mut snapshot = BTreeMap::new();
        snapshot.insert(
            "dns_connection_count".to_string(),
            items_scanned.to_string(),
        );

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "DNS 接続 {}件をスキャンしました（問題: {}件）",
                items_scanned, issues_found
            ),
            snapshot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_net_udp_v4() {
        let content = "  sl  local_address rem_address   st tx_queue:rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
                        0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12345 2 0000000000000000 0\n\
                        1: 00000000:C350 0100007F:0035 07 00000100:00000200 00:00000000 00000000  1000        0 67890 2 0000000000000000 0";
        let entries = parse_proc_net_udp(content, false);
        assert_eq!(entries.len(), 2);

        // First entry: local 127.0.0.1:53
        assert_eq!(entries[0].local_port, 53);
        assert_eq!(entries[0].remote_port, 0);
        assert_eq!(entries[0].tx_queue, 0);
        assert_eq!(entries[0].rx_queue, 0);

        // Second entry: remote 127.0.0.1:53, tx_queue=256, rx_queue=512
        assert_eq!(entries[1].remote_port, 53);
        assert_eq!(entries[1].tx_queue, 0x100);
        assert_eq!(entries[1].rx_queue, 0x200);
    }

    #[test]
    fn test_parse_proc_net_udp_v6() {
        let content = "  sl  local_address                         remote_address                        st tx_queue:rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
                        0: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12345 2 0000000000000000 0";
        let entries = parse_proc_net_udp(content, true);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].local_port, 53);
    }

    #[test]
    fn test_parse_proc_net_udp_empty() {
        let content = "  sl  local_address rem_address   st tx_queue:rx_queue\n";
        let entries = parse_proc_net_udp(content, false);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_addr_port_v4() {
        let result = parse_addr_port_v4("0100007F:0035");
        assert!(result.is_some());
        let (addr, port) = result.unwrap();
        assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(port, 53);
    }

    #[test]
    fn test_parse_addr_port_v4_invalid() {
        assert!(parse_addr_port_v4("invalid").is_none());
        assert!(parse_addr_port_v4("GGGGGGGG:0035").is_none());
    }

    #[test]
    fn test_parse_addr_port_v6() {
        let result = parse_addr_port_v6("00000000000000000000000001000000:0035");
        assert!(result.is_some());
        let (_addr, port) = result.unwrap();
        assert_eq!(port, 53);
    }

    #[test]
    fn test_parse_addr_port_v6_invalid_length() {
        assert!(parse_addr_port_v6("0000:0035").is_none());
    }

    #[test]
    fn test_parse_queue() {
        let result = parse_queue("00000100:00000200");
        assert!(result.is_some());
        let (tx, rx) = result.unwrap();
        assert_eq!(tx, 0x100);
        assert_eq!(rx, 0x200);
    }

    #[test]
    fn test_parse_queue_zero() {
        let (tx, rx) = parse_queue("00000000:00000000").unwrap();
        assert_eq!(tx, 0);
        assert_eq!(rx, 0);
    }

    #[test]
    fn test_parse_queue_invalid() {
        assert!(parse_queue("invalid").is_none());
    }

    #[test]
    fn test_parse_resolv_conf() {
        let content = "# DNS configuration\n\
                       nameserver 8.8.8.8\n\
                       nameserver 8.8.4.4\n\
                       nameserver 2001:4860:4860::8888\n\
                       search example.com\n\
                       options ndots:5\n";
        let servers = parse_resolv_conf(content);
        assert_eq!(servers.len(), 3);
        assert!(servers.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(servers.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))));
    }

    #[test]
    fn test_parse_resolv_conf_empty() {
        let servers = parse_resolv_conf("");
        assert!(servers.is_empty());
    }

    #[test]
    fn test_parse_resolv_conf_comments_only() {
        let content = "# comment\n# another comment\n";
        let servers = parse_resolv_conf(content);
        assert!(servers.is_empty());
    }

    #[test]
    fn test_filter_dns_entries() {
        let entries = vec![
            UdpEntry {
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                local_port: 12345,
                remote_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                remote_port: 53,
                tx_queue: 0,
                rx_queue: 0,
            },
            UdpEntry {
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                local_port: 12346,
                remote_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                remote_port: 80,
                tx_queue: 0,
                rx_queue: 0,
            },
            UdpEntry {
                local_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                local_port: 53,
                remote_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                remote_port: 53,
                tx_queue: 0,
                rx_queue: 0,
            },
        ];

        let dns = filter_dns_entries(&entries);
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].remote_addr, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_check_high_query_rate_below_threshold() {
        let entries = vec![UdpEntry {
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            local_port: 12345,
            remote_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            remote_port: 53,
            tx_queue: 0,
            rx_queue: 0,
        }];
        let dns = filter_dns_entries(&entries);
        assert!(DnsQueryMonitorModule::check_high_query_rate(&dns, 100).is_none());
    }

    #[test]
    fn test_check_high_query_rate_at_threshold() {
        let entries: Vec<UdpEntry> = (0..5)
            .map(|i| UdpEntry {
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                local_port: 12345 + i,
                remote_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                remote_port: 53,
                tx_queue: 0,
                rx_queue: 0,
            })
            .collect();
        let dns = filter_dns_entries(&entries);
        assert_eq!(
            DnsQueryMonitorModule::check_high_query_rate(&dns, 5),
            Some(5)
        );
    }

    #[test]
    fn test_check_unknown_dns_servers() {
        let entries = vec![
            UdpEntry {
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                local_port: 12345,
                remote_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                remote_port: 53,
                tx_queue: 0,
                rx_queue: 0,
            },
            UdpEntry {
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                local_port: 12346,
                remote_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                remote_port: 53,
                tx_queue: 0,
                rx_queue: 0,
            },
        ];
        let dns = filter_dns_entries(&entries);
        let mut known = HashSet::new();
        known.insert(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let whitelist = HashSet::new();

        let unknown = DnsQueryMonitorModule::check_unknown_dns_servers(&dns, &known, &whitelist);
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_check_unknown_dns_servers_with_whitelist() {
        let entries = vec![UdpEntry {
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            local_port: 12345,
            remote_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            remote_port: 53,
            tx_queue: 0,
            rx_queue: 0,
        }];
        let dns = filter_dns_entries(&entries);
        let known = HashSet::new();
        let mut whitelist = HashSet::new();
        whitelist.insert(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

        let unknown = DnsQueryMonitorModule::check_unknown_dns_servers(&dns, &known, &whitelist);
        assert!(unknown.is_empty());
    }

    #[test]
    fn test_check_tunnel_suspected() {
        let entries = vec![
            UdpEntry {
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                local_port: 12345,
                remote_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                remote_port: 53,
                tx_queue: 5000,
                rx_queue: 0,
            },
            UdpEntry {
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                local_port: 12346,
                remote_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                remote_port: 53,
                tx_queue: 100,
                rx_queue: 0,
            },
        ];
        let dns = filter_dns_entries(&entries);
        let suspected = DnsQueryMonitorModule::check_tunnel_suspected(&dns, 4096);
        assert_eq!(suspected.len(), 1);
        assert_eq!(suspected[0].0, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(suspected[0].1, 5000);
    }

    #[test]
    fn test_check_tunnel_suspected_none() {
        let entries = vec![UdpEntry {
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            local_port: 12345,
            remote_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            remote_port: 53,
            tx_queue: 100,
            rx_queue: 0,
        }];
        let dns = filter_dns_entries(&entries);
        let suspected = DnsQueryMonitorModule::check_tunnel_suspected(&dns, 4096);
        assert!(suspected.is_empty());
    }

    #[test]
    fn test_is_unspecified() {
        assert!(is_unspecified(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_unspecified(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!is_unspecified(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_module_name() {
        let config = DnsQueryMonitorConfig::default();
        let module = DnsQueryMonitorModule::new(config, None);
        assert_eq!(module.name(), "dns_query_monitor");
    }

    #[test]
    fn test_init_zero_interval() {
        let config = DnsQueryMonitorConfig {
            scan_interval_secs: 0,
            ..Default::default()
        };
        let mut module = DnsQueryMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = DnsQueryMonitorConfig::default();
        let mut module = DnsQueryMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = DnsQueryMonitorConfig::default();
        let module = DnsQueryMonitorModule::new(config, None);
        let result = module.initial_scan().await;
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert!(scan.summary.contains("DNS 接続"));
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = DnsQueryMonitorConfig {
            enabled: true,
            scan_interval_secs: 1,
            ..Default::default()
        };
        let mut module = DnsQueryMonitorModule::new(config, None);
        module.init().unwrap();
        let handle = module.start().await.unwrap();
        // モジュールを停止
        module.stop().await.unwrap();
        // タスクが終了するのを待つ
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), handle).await;
    }
}
