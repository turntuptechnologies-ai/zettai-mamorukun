//! ネットワークトラフィック異常検知モジュール
//!
//! `/proc/net/dev` の統計値を定期スキャンし、トラフィック量の急激な増減を検知する。
//!
//! 検知対象:
//! - バイト数/秒の異常（DDoS、データ流出の可能性）→ Warning
//! - パケット数/秒の異常（トラフィック異常）→ Warning
//! - エラー数/秒の異常（ネットワーク障害）→ Critical
//! - パケットドロップ数/秒の異常（過負荷、攻撃の兆候）→ Critical

use crate::config::NetworkTrafficMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;
use tokio_util::sync::CancellationToken;

/// インターフェースごとのトラフィック統計
#[derive(Debug, Clone)]
struct InterfaceTraffic {
    /// 受信バイト数
    rx_bytes: u64,
    /// 送信バイト数
    tx_bytes: u64,
    /// 受信パケット数
    rx_packets: u64,
    /// 送信パケット数
    tx_packets: u64,
    /// 受信エラー数
    rx_errors: u64,
    /// 送信エラー数
    tx_errors: u64,
    /// 受信ドロップ数
    rx_drops: u64,
    /// 送信ドロップ数
    tx_drops: u64,
    /// 計測タイムスタンプ
    timestamp: Instant,
}

impl InterfaceTraffic {
    /// スナップショット用の値文字列を生成する
    fn to_snapshot_value(&self) -> String {
        format!(
            "rx_bytes={},tx_bytes={},rx_packets={},tx_packets={},rx_errors={},tx_errors={},rx_drops={},tx_drops={}",
            self.rx_bytes,
            self.tx_bytes,
            self.rx_packets,
            self.tx_packets,
            self.rx_errors,
            self.tx_errors,
            self.rx_drops,
            self.tx_drops
        )
    }
}

/// `/proc/net/dev` をパースし、各インターフェースのトラフィック統計を収集する
///
/// フォーマット:
/// ```text
/// Inter-|   Receive                                                |  Transmit
///  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
///     lo: 1234  12  0  0  0  0  0  0  1234  12  0  0  0  0  0  0
/// ```
fn collect_traffic(
    proc_net_dev_path: &Path,
    ignore_interfaces: &[String],
) -> BTreeMap<String, InterfaceTraffic> {
    let content = match std::fs::read_to_string(proc_net_dev_path) {
        Ok(content) => content,
        Err(e) => {
            tracing::debug!(
                path = %proc_net_dev_path.display(),
                error = %e,
                "/proc/net/dev の読み取りに失敗しました"
            );
            return BTreeMap::new();
        }
    };

    let now = Instant::now();
    let mut result = BTreeMap::new();

    for line in content.lines() {
        // インターフェース行は "iface:" で区切られる
        let Some((iface_part, stats_part)) = line.split_once(':') else {
            continue;
        };

        let iface = iface_part.trim();
        if iface.is_empty() {
            continue;
        }

        // 無視リストに含まれるインターフェースはスキップ
        if ignore_interfaces.iter().any(|ig| ig == iface) {
            continue;
        }

        let values: Vec<u64> = stats_part
            .split_whitespace()
            .filter_map(|v| v.parse::<u64>().ok())
            .collect();

        // /proc/net/dev は 16 個の数値フィールドを持つ（Receive 8 + Transmit 8）
        if values.len() < 16 {
            tracing::debug!(
                interface = %iface,
                fields = values.len(),
                "フィールド数が不足しています"
            );
            continue;
        }

        result.insert(
            iface.to_string(),
            InterfaceTraffic {
                rx_bytes: values[0],
                rx_packets: values[1],
                rx_errors: values[2],
                rx_drops: values[3],
                tx_bytes: values[8],
                tx_packets: values[9],
                tx_errors: values[10],
                tx_drops: values[11],
                timestamp: now,
            },
        );
    }

    result
}

/// トラフィック異常の種類
enum AnomalyKind {
    Bytes,
    Packets,
    Errors,
    Drops,
}

/// ベースラインと現在のトラフィック統計を比較し、異常を検知してイベントを発行する
///
/// 検知した問題数を返す。
fn compare_and_report(
    baseline: &BTreeMap<String, InterfaceTraffic>,
    current: &BTreeMap<String, InterfaceTraffic>,
    config: &NetworkTrafficMonitorConfig,
    event_bus: &Option<EventBus>,
) -> usize {
    let mut issues = 0;

    for (iface, cur) in current {
        let Some(prev) = baseline.get(iface) else {
            // 新規インターフェース — ベースラインがないので判定しない
            tracing::debug!(interface = %iface, "新規インターフェースを検出（ベースライン取得）");
            continue;
        };

        let elapsed_secs = cur.timestamp.duration_since(prev.timestamp).as_secs_f64();
        if elapsed_secs <= 0.0 {
            continue;
        }

        // カウンタのオーバーフロー: 差分が負になった場合はスキップ
        let calc_rate = |cur_val: u64, prev_val: u64| -> f64 {
            if cur_val >= prev_val {
                (cur_val - prev_val) as f64 / elapsed_secs
            } else {
                // カウンタリセット — 異常判定しない
                0.0
            }
        };

        let rx_bytes_rate = calc_rate(cur.rx_bytes, prev.rx_bytes);
        let tx_bytes_rate = calc_rate(cur.tx_bytes, prev.tx_bytes);
        let bytes_rate = rx_bytes_rate + tx_bytes_rate;

        let rx_packets_rate = calc_rate(cur.rx_packets, prev.rx_packets);
        let tx_packets_rate = calc_rate(cur.tx_packets, prev.tx_packets);
        let packets_rate = rx_packets_rate + tx_packets_rate;

        let rx_errors_rate = calc_rate(cur.rx_errors, prev.rx_errors);
        let tx_errors_rate = calc_rate(cur.tx_errors, prev.tx_errors);
        let errors_rate = rx_errors_rate + tx_errors_rate;

        let rx_drops_rate = calc_rate(cur.rx_drops, prev.rx_drops);
        let tx_drops_rate = calc_rate(cur.tx_drops, prev.tx_drops);
        let drops_rate = rx_drops_rate + tx_drops_rate;

        tracing::debug!(
            interface = %iface,
            bytes_per_sec = format!("{:.0}", bytes_rate),
            packets_per_sec = format!("{:.0}", packets_rate),
            errors_per_sec = format!("{:.0}", errors_rate),
            drops_per_sec = format!("{:.0}", drops_rate),
            "トラフィック統計"
        );

        // バイト数/秒の異常
        if config.threshold_bytes_per_sec > 0 && bytes_rate > config.threshold_bytes_per_sec as f64
        {
            issues += report_anomaly(
                iface,
                AnomalyKind::Bytes,
                bytes_rate,
                config.threshold_bytes_per_sec,
                event_bus,
            );
        }

        // パケット数/秒の異常
        if config.threshold_packets_per_sec > 0
            && packets_rate > config.threshold_packets_per_sec as f64
        {
            issues += report_anomaly(
                iface,
                AnomalyKind::Packets,
                packets_rate,
                config.threshold_packets_per_sec,
                event_bus,
            );
        }

        // エラー数/秒の異常
        if config.threshold_errors_per_sec > 0
            && errors_rate > config.threshold_errors_per_sec as f64
        {
            issues += report_anomaly(
                iface,
                AnomalyKind::Errors,
                errors_rate,
                config.threshold_errors_per_sec,
                event_bus,
            );
        }

        // ドロップ数/秒の異常
        if config.threshold_drops_per_sec > 0 && drops_rate > config.threshold_drops_per_sec as f64
        {
            issues += report_anomaly(
                iface,
                AnomalyKind::Drops,
                drops_rate,
                config.threshold_drops_per_sec,
                event_bus,
            );
        }
    }

    issues
}

/// 異常を報告し、SecurityEvent を発行する。1 を返す。
fn report_anomaly(
    iface: &str,
    kind: AnomalyKind,
    rate: f64,
    threshold: u64,
    event_bus: &Option<EventBus>,
) -> usize {
    let (event_type, severity, unit, label) = match kind {
        AnomalyKind::Bytes => (
            "traffic_bytes_anomaly",
            Severity::Warning,
            "bytes/s",
            "トラフィック量",
        ),
        AnomalyKind::Packets => (
            "traffic_packets_anomaly",
            Severity::Warning,
            "packets/s",
            "パケット数",
        ),
        AnomalyKind::Errors => (
            "traffic_errors_detected",
            Severity::Critical,
            "errors/s",
            "ネットワークエラー",
        ),
        AnomalyKind::Drops => (
            "traffic_drops_detected",
            Severity::Critical,
            "drops/s",
            "パケットドロップ",
        ),
    };

    let message = format!(
        "{} で{}が異常: {:.0} {} （閾値: {} {}）",
        iface, label, rate, unit, threshold, unit
    );

    match severity {
        Severity::Critical => {
            tracing::error!(
                interface = %iface,
                rate = format!("{:.0}", rate),
                threshold = threshold,
                "{}", message
            );
        }
        _ => {
            tracing::warn!(
                interface = %iface,
                rate = format!("{:.0}", rate),
                threshold = threshold,
                "{}", message
            );
        }
    }

    if let Some(bus) = event_bus {
        bus.publish(
            SecurityEvent::new(event_type, severity, "network_traffic_monitor", &message)
                .with_details(format!(
                    "interface={}, rate={:.0}, threshold={}, unit={}",
                    iface, rate, threshold, unit
                )),
        );
    }

    1
}

/// ネットワークトラフィック異常検知モジュール
///
/// `/proc/net/dev` の統計値を定期スキャンし、トラフィック量の急激な増減を
/// 検知する。DDoS やデータ流出の早期警告に有効。
pub struct NetworkTrafficMonitorModule {
    config: NetworkTrafficMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl NetworkTrafficMonitorModule {
    /// 新しいネットワークトラフィック異常検知モジュールを作成する
    pub fn new(config: NetworkTrafficMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

impl Module for NetworkTrafficMonitorModule {
    fn name(&self) -> &str {
        "network_traffic_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            proc_net_dev_path = %self.config.proc_net_dev_path.display(),
            ignore_interfaces = ?self.config.ignore_interfaces,
            threshold_bytes_per_sec = self.config.threshold_bytes_per_sec,
            threshold_packets_per_sec = self.config.threshold_packets_per_sec,
            threshold_errors_per_sec = self.config.threshold_errors_per_sec,
            threshold_drops_per_sec = self.config.threshold_drops_per_sec,
            "ネットワークトラフィック異常検知モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let scan_interval_secs = self.config.scan_interval_secs;
        let proc_net_dev_path = self.config.proc_net_dev_path.clone();
        let ignore_interfaces = self.config.ignore_interfaces.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let config = self.config.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            // 初回スキャンでベースラインを構築
            let mut baseline = collect_traffic(&proc_net_dev_path, &ignore_interfaces);

            tracing::info!(
                interfaces = baseline.len(),
                "ネットワークトラフィックのベースラインを構築しました"
            );

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ネットワークトラフィック異常検知モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = collect_traffic(&proc_net_dev_path, &ignore_interfaces);
                        let issues = compare_and_report(&baseline, &current, &config, &event_bus);

                        if issues == 0 {
                            tracing::debug!("ネットワークトラフィックに異常はありません");
                        }

                        // ベースラインを更新
                        baseline = current;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = Instant::now();

        let traffic = collect_traffic(
            &self.config.proc_net_dev_path,
            &self.config.ignore_interfaces,
        );

        // 起動時スキャンではベースライン取得のみ（差分なしのため異常検知は行わない）
        let mut snapshot: BTreeMap<String, String> = BTreeMap::new();
        for (iface, stats) in &traffic {
            let key = format!("iface:{}", iface);
            snapshot.insert(key, stats.to_snapshot_value());
        }

        let duration = start.elapsed();

        tracing::info!(
            interfaces = traffic.len(),
            "起動時スキャン: ネットワークトラフィック統計を取得しました"
        );

        Ok(InitialScanResult {
            items_scanned: traffic.len(),
            issues_found: 0,
            duration,
            summary: format!(
                "ネットワークトラフィック {}個のインターフェースをスキャン（ベースライン取得）",
                traffic.len()
            ),
            snapshot,
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
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// テスト用の /proc/net/dev ファイルを作成する
    fn create_test_proc_net_dev(content: &str) -> TempDir {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("dev");
        std::fs::write(path, content).unwrap();
        tmp
    }

    fn typical_proc_net_dev() -> &'static str {
        "Inter-|   Receive                                                |  Transmit\n \
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    \
         lo: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n  \
         eth0: 500000 5000 0 0 0 0 0 0 300000 3000 0 0 0 0 0 0\n  \
         wlan0: 100000 1000 5 2 0 0 0 0 50000 500 1 0 0 0 0 0\n"
    }

    fn make_config(proc_net_dev_path: &Path) -> NetworkTrafficMonitorConfig {
        NetworkTrafficMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            ignore_interfaces: Vec::new(),
            proc_net_dev_path: proc_net_dev_path.to_path_buf(),
            threshold_bytes_per_sec: 104_857_600,
            threshold_packets_per_sec: 100_000,
            threshold_errors_per_sec: 10,
            threshold_drops_per_sec: 10,
        }
    }

    // --- collect_traffic ---

    #[test]
    fn test_collect_traffic_typical() {
        let tmp = create_test_proc_net_dev(typical_proc_net_dev());
        let path = tmp.path().join("dev");
        let traffic = collect_traffic(&path, &[]);

        assert_eq!(traffic.len(), 3);
        assert!(traffic.contains_key("lo"));
        assert!(traffic.contains_key("eth0"));
        assert!(traffic.contains_key("wlan0"));

        let eth0 = &traffic["eth0"];
        assert_eq!(eth0.rx_bytes, 500_000);
        assert_eq!(eth0.tx_bytes, 300_000);
        assert_eq!(eth0.rx_packets, 5000);
        assert_eq!(eth0.tx_packets, 3000);
        assert_eq!(eth0.rx_errors, 0);
        assert_eq!(eth0.tx_errors, 0);

        let wlan0 = &traffic["wlan0"];
        assert_eq!(wlan0.rx_errors, 5);
        assert_eq!(wlan0.tx_errors, 1);
        assert_eq!(wlan0.rx_drops, 2);
    }

    #[test]
    fn test_collect_traffic_with_ignore() {
        let tmp = create_test_proc_net_dev(typical_proc_net_dev());
        let path = tmp.path().join("dev");
        let ignore = vec!["lo".to_string()];
        let traffic = collect_traffic(&path, &ignore);

        assert_eq!(traffic.len(), 2);
        assert!(!traffic.contains_key("lo"));
        assert!(traffic.contains_key("eth0"));
    }

    #[test]
    fn test_collect_traffic_nonexistent_path() {
        let traffic = collect_traffic(Path::new("/nonexistent/path"), &[]);
        assert!(traffic.is_empty());
    }

    #[test]
    fn test_collect_traffic_malformed_line() {
        let content = "Inter-|   Receive\n face |bytes ...\n  eth0: 100 200\n";
        let tmp = create_test_proc_net_dev(content);
        let path = tmp.path().join("dev");
        let traffic = collect_traffic(&path, &[]);

        // フィールド不足のため無視される
        assert!(traffic.is_empty());
    }

    #[test]
    fn test_collect_traffic_empty_file() {
        let tmp = create_test_proc_net_dev("");
        let path = tmp.path().join("dev");
        let traffic = collect_traffic(&path, &[]);
        assert!(traffic.is_empty());
    }

    // --- compare_and_report ---

    #[test]
    fn test_compare_no_anomaly() {
        let now = Instant::now();
        let mut baseline = BTreeMap::new();
        baseline.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 1000,
                tx_bytes: 500,
                rx_packets: 10,
                tx_packets: 5,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 0,
                tx_drops: 0,
                timestamp: now - std::time::Duration::from_secs(30),
            },
        );

        let mut current = BTreeMap::new();
        current.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 2000,
                tx_bytes: 1000,
                rx_packets: 20,
                tx_packets: 10,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 0,
                tx_drops: 0,
                timestamp: now,
            },
        );

        let config = NetworkTrafficMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            ignore_interfaces: Vec::new(),
            proc_net_dev_path: PathBuf::from("/proc/net/dev"),
            threshold_bytes_per_sec: 104_857_600,
            threshold_packets_per_sec: 100_000,
            threshold_errors_per_sec: 10,
            threshold_drops_per_sec: 10,
        };

        let issues = compare_and_report(&baseline, &current, &config, &None);
        assert_eq!(issues, 0);
    }

    #[test]
    fn test_compare_bytes_anomaly() {
        let now = Instant::now();
        let mut baseline = BTreeMap::new();
        baseline.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 0,
                tx_drops: 0,
                timestamp: now - std::time::Duration::from_secs(1),
            },
        );

        let mut current = BTreeMap::new();
        current.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 200_000_000, // 200MB in 1 sec = 200MB/s > 100MB/s threshold
                tx_bytes: 0,
                rx_packets: 100,
                tx_packets: 0,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 0,
                tx_drops: 0,
                timestamp: now,
            },
        );

        let config = NetworkTrafficMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            ignore_interfaces: Vec::new(),
            proc_net_dev_path: PathBuf::from("/proc/net/dev"),
            threshold_bytes_per_sec: 104_857_600,
            threshold_packets_per_sec: 100_000,
            threshold_errors_per_sec: 10,
            threshold_drops_per_sec: 10,
        };

        let issues = compare_and_report(&baseline, &current, &config, &None);
        assert_eq!(issues, 1);
    }

    #[test]
    fn test_compare_errors_anomaly() {
        let now = Instant::now();
        let mut baseline = BTreeMap::new();
        baseline.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 0,
                tx_drops: 0,
                timestamp: now - std::time::Duration::from_secs(1),
            },
        );

        let mut current = BTreeMap::new();
        current.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_errors: 15, // 15 errors/s > 10 threshold
                tx_errors: 0,
                rx_drops: 0,
                tx_drops: 0,
                timestamp: now,
            },
        );

        let config = NetworkTrafficMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            ignore_interfaces: Vec::new(),
            proc_net_dev_path: PathBuf::from("/proc/net/dev"),
            threshold_bytes_per_sec: 104_857_600,
            threshold_packets_per_sec: 100_000,
            threshold_errors_per_sec: 10,
            threshold_drops_per_sec: 10,
        };

        let issues = compare_and_report(&baseline, &current, &config, &None);
        assert_eq!(issues, 1);
    }

    #[test]
    fn test_compare_drops_anomaly() {
        let now = Instant::now();
        let mut baseline = BTreeMap::new();
        baseline.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 0,
                tx_drops: 0,
                timestamp: now - std::time::Duration::from_secs(1),
            },
        );

        let mut current = BTreeMap::new();
        current.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 20, // 20 drops/s > 10 threshold
                tx_drops: 0,
                timestamp: now,
            },
        );

        let config = NetworkTrafficMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            ignore_interfaces: Vec::new(),
            proc_net_dev_path: PathBuf::from("/proc/net/dev"),
            threshold_bytes_per_sec: 104_857_600,
            threshold_packets_per_sec: 100_000,
            threshold_errors_per_sec: 10,
            threshold_drops_per_sec: 10,
        };

        let issues = compare_and_report(&baseline, &current, &config, &None);
        assert_eq!(issues, 1);
    }

    #[test]
    fn test_compare_multiple_anomalies() {
        let now = Instant::now();
        let mut baseline = BTreeMap::new();
        baseline.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 0,
                tx_drops: 0,
                timestamp: now - std::time::Duration::from_secs(1),
            },
        );

        let mut current = BTreeMap::new();
        current.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 200_000_000,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_errors: 50,
                tx_errors: 0,
                rx_drops: 50,
                tx_drops: 0,
                timestamp: now,
            },
        );

        let config = NetworkTrafficMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            ignore_interfaces: Vec::new(),
            proc_net_dev_path: PathBuf::from("/proc/net/dev"),
            threshold_bytes_per_sec: 104_857_600,
            threshold_packets_per_sec: 100_000,
            threshold_errors_per_sec: 10,
            threshold_drops_per_sec: 10,
        };

        let issues = compare_and_report(&baseline, &current, &config, &None);
        // bytes + errors + drops = 3
        assert_eq!(issues, 3);
    }

    #[test]
    fn test_compare_new_interface_no_baseline() {
        let baseline = BTreeMap::new();

        let mut current = BTreeMap::new();
        current.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 999_999_999,
                tx_bytes: 999_999_999,
                rx_packets: 999_999,
                tx_packets: 999_999,
                rx_errors: 999,
                tx_errors: 999,
                rx_drops: 999,
                tx_drops: 999,
                timestamp: Instant::now(),
            },
        );

        let config = NetworkTrafficMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            ignore_interfaces: Vec::new(),
            proc_net_dev_path: PathBuf::from("/proc/net/dev"),
            threshold_bytes_per_sec: 1,
            threshold_packets_per_sec: 1,
            threshold_errors_per_sec: 1,
            threshold_drops_per_sec: 1,
        };

        // ベースラインがないインターフェースは判定しない
        let issues = compare_and_report(&baseline, &current, &config, &None);
        assert_eq!(issues, 0);
    }

    #[test]
    fn test_compare_counter_overflow() {
        let now = Instant::now();
        let mut baseline = BTreeMap::new();
        baseline.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 1_000_000,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 0,
                tx_drops: 0,
                timestamp: now - std::time::Duration::from_secs(1),
            },
        );

        let mut current = BTreeMap::new();
        current.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 500, // カウンタがリセットされた（前回より小さい）
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 0,
                tx_drops: 0,
                timestamp: now,
            },
        );

        let config = NetworkTrafficMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            ignore_interfaces: Vec::new(),
            proc_net_dev_path: PathBuf::from("/proc/net/dev"),
            threshold_bytes_per_sec: 1,
            threshold_packets_per_sec: 1,
            threshold_errors_per_sec: 1,
            threshold_drops_per_sec: 1,
        };

        // カウンタリセット時はレート 0 として処理される
        let issues = compare_and_report(&baseline, &current, &config, &None);
        assert_eq!(issues, 0);
    }

    #[test]
    fn test_compare_threshold_zero_disables_check() {
        let now = Instant::now();
        let mut baseline = BTreeMap::new();
        baseline.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_errors: 0,
                tx_errors: 0,
                rx_drops: 0,
                tx_drops: 0,
                timestamp: now - std::time::Duration::from_secs(1),
            },
        );

        let mut current = BTreeMap::new();
        current.insert(
            "eth0".to_string(),
            InterfaceTraffic {
                rx_bytes: 999_999_999,
                tx_bytes: 999_999_999,
                rx_packets: 999_999,
                tx_packets: 999_999,
                rx_errors: 999,
                tx_errors: 999,
                rx_drops: 999,
                tx_drops: 999,
                timestamp: now,
            },
        );

        let config = NetworkTrafficMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            ignore_interfaces: Vec::new(),
            proc_net_dev_path: PathBuf::from("/proc/net/dev"),
            threshold_bytes_per_sec: 0, // 無効
            threshold_packets_per_sec: 0,
            threshold_errors_per_sec: 0,
            threshold_drops_per_sec: 0,
        };

        // 全閾値が 0 のためチェック無効
        let issues = compare_and_report(&baseline, &current, &config, &None);
        assert_eq!(issues, 0);
    }

    // --- InterfaceTraffic ---

    #[test]
    fn test_to_snapshot_value() {
        let traffic = InterfaceTraffic {
            rx_bytes: 100,
            tx_bytes: 200,
            rx_packets: 10,
            tx_packets: 20,
            rx_errors: 1,
            tx_errors: 2,
            rx_drops: 3,
            tx_drops: 4,
            timestamp: Instant::now(),
        };

        let value = traffic.to_snapshot_value();
        assert!(value.contains("rx_bytes=100"));
        assert!(value.contains("tx_bytes=200"));
        assert!(value.contains("rx_packets=10"));
        assert!(value.contains("tx_packets=20"));
        assert!(value.contains("rx_errors=1"));
        assert!(value.contains("tx_errors=2"));
        assert!(value.contains("rx_drops=3"));
        assert!(value.contains("tx_drops=4"));
    }

    // --- Module lifecycle ---

    #[test]
    fn test_init_zero_interval() {
        let tmp = TempDir::new().unwrap();
        let mut config = make_config(&tmp.path().join("dev"));
        config.scan_interval_secs = 0;
        let mut module = NetworkTrafficMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let tmp = create_test_proc_net_dev(typical_proc_net_dev());
        let config = make_config(&tmp.path().join("dev"));
        let mut module = NetworkTrafficMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let tmp = create_test_proc_net_dev(typical_proc_net_dev());
        let config = make_config(&tmp.path().join("dev"));
        let mut module = NetworkTrafficMonitorModule::new(config, None);
        assert!(module.init().is_ok());
        assert!(module.start().await.is_ok());
        assert!(module.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let tmp = create_test_proc_net_dev(typical_proc_net_dev());
        let mut config = make_config(&tmp.path().join("dev"));
        config.ignore_interfaces = vec!["lo".to_string()];
        let module = NetworkTrafficMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 2); // eth0, wlan0 (lo is ignored)
        assert_eq!(result.issues_found, 0);
        assert!(result.snapshot.contains_key("iface:eth0"));
        assert!(result.snapshot.contains_key("iface:wlan0"));
        assert!(!result.snapshot.contains_key("iface:lo"));
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let tmp = create_test_proc_net_dev("");
        let config = make_config(&tmp.path().join("dev"));
        let module = NetworkTrafficMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }

    // --- report_anomaly ---

    #[test]
    fn test_report_anomaly_returns_one() {
        let count = report_anomaly(
            "eth0",
            AnomalyKind::Bytes,
            200_000_000.0,
            100_000_000,
            &None,
        );
        assert_eq!(count, 1);
    }

    #[test]
    fn test_report_anomaly_errors_severity() {
        let count = report_anomaly("eth0", AnomalyKind::Errors, 50.0, 10, &None);
        assert_eq!(count, 1);
    }
}
