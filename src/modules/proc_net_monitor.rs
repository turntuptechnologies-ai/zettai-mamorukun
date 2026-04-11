//! /proc/net/ 監視モジュール
//!
//! `/proc/net/route` と `/proc/net/arp` を定期スキャンし、
//! ルーティングテーブルや ARP テーブルの不正変更を検知する。
//!
//! 検知対象:
//! - ARP エントリの MAC アドレス変更（ARP スプーフィング疑い）→ Critical
//! - デフォルトゲートウェイ変更 → High
//! - ルートエントリの変更・削除 → High
//! - ルートエントリの追加 → Warning
//! - ARP エントリの追加 → Info
//! - ARP エントリの削除 → Warning

use crate::config::ProcNetMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

/// /proc/net/route の 1 エントリ
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteEntry {
    iface: String,
    destination: String,
    gateway: String,
    flags: String,
    metric: String,
    mask: String,
}

impl RouteEntry {
    /// デフォルトゲートウェイかどうかを返す
    fn is_default_gateway(&self) -> bool {
        self.destination == "00000000" && self.mask == "00000000"
    }
}

/// /proc/net/arp の 1 エントリ
#[derive(Debug, Clone, PartialEq, Eq)]
struct ArpEntry {
    ip: String,
    hw_address: String,
    device: String,
}

/// /proc/net/ のスナップショット
#[derive(Debug, Clone)]
struct ProcNetSnapshot {
    routes: Vec<RouteEntry>,
    /// IP アドレス → ArpEntry のマップ
    arp_entries: BTreeMap<String, ArpEntry>,
}

/// /proc/net/route を読み取り、RouteEntry のリストを返す
///
/// パース失敗行はスキップする。ファイル読み取り失敗時は空 Vec を返す。
fn parse_route_file(path: &str) -> Vec<RouteEntry> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(path = %path, error = %e, "/proc/net/route の読み取りに失敗しました");
            return Vec::new();
        }
    };

    let mut entries = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
        if cols.len() < 8 {
            tracing::debug!(line = %line, "/proc/net/route の行をパースできませんでした（カラム不足）");
            continue;
        }
        entries.push(RouteEntry {
            iface: cols[0].to_string(),
            destination: cols[1].to_lowercase(),
            gateway: cols[2].to_lowercase(),
            flags: cols[3].to_lowercase(),
            metric: cols[6].to_string(),
            mask: cols[7].to_lowercase(),
        });
    }
    entries
}

/// /proc/net/arp を読み取り、IP→ArpEntry の BTreeMap を返す
///
/// パース失敗行はスキップする。ファイル読み取り失敗時は空 BTreeMap を返す。
fn parse_arp_file(path: &str) -> BTreeMap<String, ArpEntry> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(path = %path, error = %e, "/proc/net/arp の読み取りに失敗しました");
            return BTreeMap::new();
        }
    };

    let mut entries = BTreeMap::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // IP address HW type Flags HW address Mask Device
        if cols.len() < 6 {
            tracing::debug!(line = %line, "/proc/net/arp の行をパースできませんでした（カラム不足）");
            continue;
        }
        let ip = cols[0].to_string();
        let entry = ArpEntry {
            ip: ip.clone(),
            hw_address: cols[3].to_lowercase(),
            device: cols[5].to_string(),
        };
        entries.insert(ip, entry);
    }
    entries
}

/// /proc/net/ のスナップショットを取得する
fn take_snapshot(route_path: &str, arp_path: &str) -> ProcNetSnapshot {
    ProcNetSnapshot {
        routes: parse_route_file(route_path),
        arp_entries: parse_arp_file(arp_path),
    }
}

/// ベースラインと現在のスナップショットを比較し、変更を検知してイベント発行する
///
/// 変更があった場合は `true` を返す。
fn detect_and_report(
    baseline: &ProcNetSnapshot,
    current: &ProcNetSnapshot,
    event_bus: &Option<EventBus>,
) -> bool {
    let mut has_changes = false;

    // ARP スプーフィング検知（MAC アドレス変更）
    for (ip, current_arp) in &current.arp_entries {
        if let Some(baseline_arp) = baseline.arp_entries.get(ip)
            && baseline_arp.hw_address != current_arp.hw_address
        {
            let details = format!(
                "IP={}, 旧MAC={}, 新MAC={}, デバイス={}",
                ip, baseline_arp.hw_address, current_arp.hw_address, current_arp.device
            );
            tracing::error!(
                ip = %ip,
                old_mac = %baseline_arp.hw_address,
                new_mac = %current_arp.hw_address,
                device = %current_arp.device,
                "ARP スプーフィング疑い: MAC アドレスが変更されました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "arp_spoofing_detected",
                        Severity::Critical,
                        "proc_net_monitor",
                        "ARP スプーフィング疑い: MAC アドレスが変更されました",
                    )
                    .with_details(details),
                );
            }
            has_changes = true;
        }
    }

    // ARP エントリの削除
    for (ip, baseline_arp) in &baseline.arp_entries {
        if !current.arp_entries.contains_key(ip) {
            let details = format!(
                "IP={}, MAC={}, デバイス={}",
                ip, baseline_arp.hw_address, baseline_arp.device
            );
            tracing::warn!(
                ip = %ip,
                mac = %baseline_arp.hw_address,
                device = %baseline_arp.device,
                "ARP エントリが削除されました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "arp_entry_removed",
                        Severity::Warning,
                        "proc_net_monitor",
                        "ARP エントリが削除されました",
                    )
                    .with_details(details),
                );
            }
            has_changes = true;
        }
    }

    // ARP エントリの追加
    for (ip, current_arp) in &current.arp_entries {
        if !baseline.arp_entries.contains_key(ip) {
            let details = format!(
                "IP={}, MAC={}, デバイス={}",
                ip, current_arp.hw_address, current_arp.device
            );
            tracing::info!(
                ip = %ip,
                mac = %current_arp.hw_address,
                device = %current_arp.device,
                "ARP エントリが追加されました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "arp_entry_added",
                        Severity::Info,
                        "proc_net_monitor",
                        "ARP エントリが追加されました",
                    )
                    .with_details(details),
                );
            }
            has_changes = true;
        }
    }

    // ルートエントリの比較: (destination, mask) をキーとして使用
    let baseline_routes: BTreeMap<(&str, &str), &RouteEntry> = baseline
        .routes
        .iter()
        .map(|r| ((r.destination.as_str(), r.mask.as_str()), r))
        .collect();

    let current_routes: BTreeMap<(&str, &str), &RouteEntry> = current
        .routes
        .iter()
        .map(|r| ((r.destination.as_str(), r.mask.as_str()), r))
        .collect();

    // ルート変更・削除の検知
    for ((dest, mask), baseline_route) in &baseline_routes {
        if let Some(current_route) = current_routes.get(&(*dest, *mask)) {
            // 同一 dest+mask でエントリが変化した場合
            if baseline_route.gateway != current_route.gateway
                || baseline_route.flags != current_route.flags
                || baseline_route.iface != current_route.iface
            {
                if baseline_route.is_default_gateway() {
                    let details = format!(
                        "旧ゲートウェイ={}, 新ゲートウェイ={}, インターフェース={}",
                        baseline_route.gateway, current_route.gateway, current_route.iface
                    );
                    tracing::error!(
                        old_gateway = %baseline_route.gateway,
                        new_gateway = %current_route.gateway,
                        iface = %current_route.iface,
                        "デフォルトゲートウェイが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "default_gateway_changed",
                                Severity::Critical,
                                "proc_net_monitor",
                                "デフォルトゲートウェイが変更されました",
                            )
                            .with_details(details),
                        );
                    }
                } else {
                    let details = format!(
                        "宛先={}, マスク={}, 旧ゲートウェイ={}, 新ゲートウェイ={}, インターフェース={}",
                        dest,
                        mask,
                        baseline_route.gateway,
                        current_route.gateway,
                        current_route.iface
                    );
                    tracing::error!(
                        destination = %dest,
                        mask = %mask,
                        old_gateway = %baseline_route.gateway,
                        new_gateway = %current_route.gateway,
                        iface = %current_route.iface,
                        "ルートエントリが変更されました"
                    );
                    if let Some(bus) = event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "route_entry_changed",
                                Severity::Critical,
                                "proc_net_monitor",
                                "ルートエントリが変更されました",
                            )
                            .with_details(details),
                        );
                    }
                }
                has_changes = true;
            }
        } else {
            // ルート削除
            let details = format!(
                "宛先={}, マスク={}, ゲートウェイ={}, インターフェース={}",
                dest, mask, baseline_route.gateway, baseline_route.iface
            );
            tracing::error!(
                destination = %dest,
                mask = %mask,
                gateway = %baseline_route.gateway,
                iface = %baseline_route.iface,
                "ルートエントリが削除されました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "route_entry_removed",
                        Severity::Critical,
                        "proc_net_monitor",
                        "ルートエントリが削除されました",
                    )
                    .with_details(details),
                );
            }
            has_changes = true;
        }
    }

    // ルート追加の検知
    for ((dest, mask), current_route) in &current_routes {
        if !baseline_routes.contains_key(&(*dest, *mask)) {
            let details = format!(
                "宛先={}, マスク={}, ゲートウェイ={}, インターフェース={}",
                dest, mask, current_route.gateway, current_route.iface
            );
            tracing::warn!(
                destination = %dest,
                mask = %mask,
                gateway = %current_route.gateway,
                iface = %current_route.iface,
                "ルートエントリが追加されました"
            );
            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "route_entry_added",
                        Severity::Warning,
                        "proc_net_monitor",
                        "ルートエントリが追加されました",
                    )
                    .with_details(details),
                );
            }
            has_changes = true;
        }
    }

    has_changes
}

/// /proc/net/ 監視モジュール
///
/// ルーティングテーブルと ARP テーブルを定期スキャンし、
/// 不正変更・ARP スプーフィングを検知する。
pub struct ProcNetMonitorModule {
    config: ProcNetMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl ProcNetMonitorModule {
    /// 新しい /proc/net/ 監視モジュールを作成する
    pub fn new(config: ProcNetMonitorConfig, event_bus: Option<EventBus>) -> Self {
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
}

impl Module for ProcNetMonitorModule {
    fn name(&self) -> &str {
        "proc_net_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            route_path = %self.config.route_path,
            arp_path = %self.config.arp_path,
            "/proc/net/ 監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let route_path = self.config.route_path.clone();
        let arp_path = self.config.arp_path.clone();
        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let baseline = take_snapshot(&route_path, &arp_path);
        tracing::info!(
            routes = baseline.routes.len(),
            arp_entries = baseline.arp_entries.len(),
            "/proc/net/ ベースラインスキャンが完了しました"
        );

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            let mut baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("/proc/net/ 監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = take_snapshot(&route_path, &arp_path);
                        let changed = detect_and_report(&baseline, &current, &event_bus);

                        if changed {
                            baseline = current;
                        } else {
                            tracing::debug!("/proc/net/ に変更はありません");
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let snapshot = take_snapshot(&self.config.route_path, &self.config.arp_path);

        let items_scanned = snapshot.routes.len() + snapshot.arp_entries.len();

        // スナップショットデータを構築
        let mut scan_snapshot: BTreeMap<String, String> = BTreeMap::new();
        for route in &snapshot.routes {
            let key = format!("route:{}+{}", route.destination, route.mask);
            scan_snapshot.insert(key, route.gateway.clone());
        }
        for (ip, arp) in &snapshot.arp_entries {
            let key = format!("arp:{}", ip);
            scan_snapshot.insert(key, arp.hw_address.clone());
        }

        tracing::info!(
            routes = snapshot.routes.len(),
            arp_entries = snapshot.arp_entries.len(),
            "起動時スキャン: /proc/net/ をスキャンしました"
        );

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!(
                "/proc/net/ {}件をスキャン（ルート: {}件, ARP: {}件）",
                items_scanned,
                snapshot.routes.len(),
                snapshot.arp_entries.len()
            ),
            snapshot: scan_snapshot,
        })
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[test]
    fn test_parse_route_file_basic() {
        let content = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                       eth0\t00000000\tFE01A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                       eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\tFFFFFF00\t0\t0\t0\n";
        let file = write_temp_file(content);
        let routes = parse_route_file(file.path().to_str().unwrap());
        assert_eq!(routes.len(), 2);
        assert!(routes[0].is_default_gateway());
        assert!(!routes[1].is_default_gateway());
        assert_eq!(routes[0].gateway, "fe01a8c0");
    }

    #[test]
    fn test_parse_route_file_skips_invalid_lines() {
        let content = "Iface\tDestination\tGateway\n\
                       eth0\t00000000\n\
                       eth0\t00000000\t00000000\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        let file = write_temp_file(content);
        let routes = parse_route_file(file.path().to_str().unwrap());
        // 2行目はカラム不足でスキップ、3行目は有効
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn test_parse_route_file_nonexistent() {
        let routes = parse_route_file("/nonexistent/path/route");
        assert!(routes.is_empty());
    }

    #[test]
    fn test_parse_arp_file_basic() {
        let content = "IP address       HW type     Flags       HW address            Mask     Device\n\
                       192.168.1.1      0x1         0x2         AA:BB:CC:DD:EE:FF     *        eth0\n\
                       192.168.1.2      0x1         0x2         11:22:33:44:55:66     *        eth0\n";
        let file = write_temp_file(content);
        let arp = parse_arp_file(file.path().to_str().unwrap());
        assert_eq!(arp.len(), 2);
        assert_eq!(arp["192.168.1.1"].hw_address, "aa:bb:cc:dd:ee:ff");
        assert_eq!(arp["192.168.1.1"].device, "eth0");
    }

    #[test]
    fn test_parse_arp_file_normalizes_mac_lowercase() {
        let content = "IP address       HW type     Flags       HW address            Mask     Device\n\
                       10.0.0.1         0x1         0x2         AA:BB:CC:DD:EE:FF     *        eth0\n";
        let file = write_temp_file(content);
        let arp = parse_arp_file(file.path().to_str().unwrap());
        assert_eq!(arp["10.0.0.1"].hw_address, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_parse_arp_file_skips_invalid_lines() {
        let content = "IP address       HW type     Flags\n\
                       10.0.0.1         0x1\n\
                       10.0.0.2         0x1         0x2         AA:BB:CC:DD:EE:FF     *        eth0\n";
        let file = write_temp_file(content);
        let arp = parse_arp_file(file.path().to_str().unwrap());
        assert_eq!(arp.len(), 1);
    }

    #[test]
    fn test_parse_arp_file_nonexistent() {
        let arp = parse_arp_file("/nonexistent/path/arp");
        assert!(arp.is_empty());
    }

    fn make_snapshot(
        routes: Vec<RouteEntry>,
        arp_entries: BTreeMap<String, ArpEntry>,
    ) -> ProcNetSnapshot {
        ProcNetSnapshot {
            routes,
            arp_entries,
        }
    }

    fn route(dest: &str, mask: &str, gw: &str, iface: &str) -> RouteEntry {
        RouteEntry {
            iface: iface.to_string(),
            destination: dest.to_string(),
            gateway: gw.to_string(),
            flags: "0003".to_string(),
            metric: "100".to_string(),
            mask: mask.to_string(),
        }
    }

    fn arp(ip: &str, mac: &str, dev: &str) -> (String, ArpEntry) {
        (
            ip.to_string(),
            ArpEntry {
                ip: ip.to_string(),
                hw_address: mac.to_string(),
                device: dev.to_string(),
            },
        )
    }

    #[test]
    fn test_detect_no_changes() {
        let snapshot = make_snapshot(
            vec![route("00000000", "00000000", "fe01a8c0", "eth0")],
            BTreeMap::from([arp("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")]),
        );
        assert!(!detect_and_report(&snapshot, &snapshot, &None));
    }

    #[test]
    fn test_detect_arp_spoofing() {
        let baseline = make_snapshot(
            vec![],
            BTreeMap::from([arp("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")]),
        );
        let current = make_snapshot(
            vec![],
            BTreeMap::from([arp("192.168.1.1", "11:22:33:44:55:66", "eth0")]),
        );
        assert!(detect_and_report(&baseline, &current, &None));
    }

    #[test]
    fn test_detect_arp_removed() {
        let baseline = make_snapshot(
            vec![],
            BTreeMap::from([arp("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")]),
        );
        let current = make_snapshot(vec![], BTreeMap::new());
        assert!(detect_and_report(&baseline, &current, &None));
    }

    #[test]
    fn test_detect_arp_added() {
        let baseline = make_snapshot(vec![], BTreeMap::new());
        let current = make_snapshot(
            vec![],
            BTreeMap::from([arp("192.168.1.1", "aa:bb:cc:dd:ee:ff", "eth0")]),
        );
        assert!(detect_and_report(&baseline, &current, &None));
    }

    #[test]
    fn test_detect_default_gateway_changed() {
        let baseline = make_snapshot(
            vec![route("00000000", "00000000", "fe01a8c0", "eth0")],
            BTreeMap::new(),
        );
        let current = make_snapshot(
            vec![route("00000000", "00000000", "0101a8c0", "eth0")],
            BTreeMap::new(),
        );
        assert!(detect_and_report(&baseline, &current, &None));
    }

    #[test]
    fn test_detect_route_changed() {
        let baseline = make_snapshot(
            vec![route("0001a8c0", "ffffff00", "00000000", "eth0")],
            BTreeMap::new(),
        );
        let current = make_snapshot(
            vec![route("0001a8c0", "ffffff00", "fe01a8c0", "eth0")],
            BTreeMap::new(),
        );
        assert!(detect_and_report(&baseline, &current, &None));
    }

    #[test]
    fn test_detect_route_removed() {
        let baseline = make_snapshot(
            vec![route("0001a8c0", "ffffff00", "00000000", "eth0")],
            BTreeMap::new(),
        );
        let current = make_snapshot(vec![], BTreeMap::new());
        assert!(detect_and_report(&baseline, &current, &None));
    }

    #[test]
    fn test_detect_route_added() {
        let baseline = make_snapshot(vec![], BTreeMap::new());
        let current = make_snapshot(
            vec![route("0001a8c0", "ffffff00", "00000000", "eth0")],
            BTreeMap::new(),
        );
        assert!(detect_and_report(&baseline, &current, &None));
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = ProcNetMonitorConfig::default();
        config.scan_interval_secs = 0;
        let mut module = ProcNetMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let config = ProcNetMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            route_path: "/proc/net/route".to_string(),
            arp_path: "/proc/net/arp".to_string(),
        };
        let mut module = ProcNetMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let route_content = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                             eth0\t00000000\tfe01a8c0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        let arp_content = "IP address       HW type     Flags       HW address            Mask     Device\n\
                           192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n";
        let route_file = write_temp_file(route_content);
        let arp_file = write_temp_file(arp_content);

        let config = ProcNetMonitorConfig {
            enabled: true,
            scan_interval_secs: 60,
            route_path: route_file.path().to_str().unwrap().to_string(),
            arp_path: arp_file.path().to_str().unwrap().to_string(),
        };
        let mut module = ProcNetMonitorModule::new(config, None);
        assert!(module.init().is_ok());
        assert!(module.start().await.is_ok());
        assert!(module.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let route_content = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                             eth0\t00000000\tfe01a8c0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                             eth0\t0001a8c0\t00000000\t0001\t0\t0\t0\tffffff00\t0\t0\t0\n";
        let arp_content = "IP address       HW type     Flags       HW address            Mask     Device\n\
                           192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n";
        let route_file = write_temp_file(route_content);
        let arp_file = write_temp_file(arp_content);

        let config = ProcNetMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            route_path: route_file.path().to_str().unwrap().to_string(),
            arp_path: arp_file.path().to_str().unwrap().to_string(),
        };
        let module = ProcNetMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        // 2 routes + 1 arp = 3
        assert_eq!(result.items_scanned, 3);
        assert_eq!(result.issues_found, 0);
        assert!(result.snapshot.contains_key("route:00000000+00000000"));
        assert!(result.snapshot.contains_key("route:0001a8c0+ffffff00"));
        assert!(result.snapshot.contains_key("arp:192.168.1.1"));
        assert_eq!(result.snapshot["arp:192.168.1.1"], "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_is_default_gateway() {
        let r = route("00000000", "00000000", "fe01a8c0", "eth0");
        assert!(r.is_default_gateway());
        let r2 = route("0001a8c0", "ffffff00", "00000000", "eth0");
        assert!(!r2.is_default_gateway());
    }
}
