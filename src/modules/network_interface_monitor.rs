//! ネットワークインターフェース監視モジュール
//!
//! `/sys/class/net/` を定期スキャンし、インターフェースの状態変化を検知する。
//!
//! 検知対象:
//! - 新規インターフェースの追加（不正なブリッジ、VPN トンネル等）→ Warning
//! - インターフェースの削除 → Info
//! - プロミスキャスモードの有効化 → Critical（パケットスニッフィングの兆候）
//! - インターフェースフラグの変更（プロミスキャス以外）→ Warning
//! - operstate の変化 → Info

use crate::config::NetworkInterfaceMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::BTreeMap;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// IFF_PROMISC フラグのビット位置
const IFF_PROMISC: u32 = 0x100;

/// インターフェース情報
#[derive(Debug, Clone, PartialEq)]
struct InterfaceInfo {
    /// インターフェース名
    name: String,
    /// フラグ値（/sys/class/net/<iface>/flags）
    flags: u32,
    /// 動作状態（/sys/class/net/<iface>/operstate）
    operstate: String,
    /// インターフェースタイプ（/sys/class/net/<iface>/type）
    if_type: String,
    /// MAC アドレス（/sys/class/net/<iface>/address）
    address: String,
}

impl InterfaceInfo {
    /// プロミスキャスモードが有効かどうかを返す
    fn is_promiscuous(&self) -> bool {
        self.flags & IFF_PROMISC != 0
    }

    /// スナップショット用の値文字列を生成する
    fn to_snapshot_value(&self) -> String {
        format!(
            "flags=0x{:x},operstate={},type={},address={}",
            self.flags, self.operstate, self.if_type, self.address
        )
    }
}

/// /sys/class/net/<iface> 配下のファイルから値を読み取る
fn read_sysfs_value(base_path: &Path, iface: &str, attr: &str) -> String {
    let path = base_path.join(iface).join(attr);
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// フラグ文字列を u32 にパースする（0x で始まる 16 進数）
fn parse_flags(flags_str: &str) -> u32 {
    let trimmed = flags_str.trim().trim_start_matches("0x");
    u32::from_str_radix(trimmed, 16).unwrap_or(0)
}

/// /sys/class/net/ を読み取り、全インターフェース情報を収集する
fn collect_interfaces(
    sys_class_net_path: &Path,
    ignore_interfaces: &[String],
) -> Vec<InterfaceInfo> {
    let entries = match std::fs::read_dir(sys_class_net_path) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!(
                path = %sys_class_net_path.display(),
                error = %e,
                "/sys/class/net の読み取りに失敗しました"
            );
            return Vec::new();
        }
    };

    let mut interfaces = Vec::new();

    for entry in entries.flatten() {
        let name = match entry.file_name().to_str() {
            Some(name) => name.to_string(),
            None => continue,
        };

        // 無視リストに含まれるインターフェースはスキップ
        if ignore_interfaces.iter().any(|ig| ig == &name) {
            continue;
        }

        let flags_str = read_sysfs_value(sys_class_net_path, &name, "flags");
        let flags = parse_flags(&flags_str);
        let operstate = read_sysfs_value(sys_class_net_path, &name, "operstate");
        let if_type = read_sysfs_value(sys_class_net_path, &name, "type");
        let address = read_sysfs_value(sys_class_net_path, &name, "address");

        interfaces.push(InterfaceInfo {
            name,
            flags,
            operstate,
            if_type,
            address,
        });
    }

    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    interfaces
}

/// ベースラインと現在のインターフェース情報を比較し、変更を検知してイベントを発行する
///
/// 検知した問題数を返す。
fn compare_and_report(
    baseline: &BTreeMap<String, InterfaceInfo>,
    current: &[InterfaceInfo],
    event_bus: &Option<EventBus>,
) -> usize {
    let mut issues = 0;

    // 現在のインターフェースを名前でマップ化
    let current_map: BTreeMap<String, &InterfaceInfo> =
        current.iter().map(|i| (i.name.clone(), i)).collect();

    // 新規追加されたインターフェースを検出
    for (name, info) in &current_map {
        if !baseline.contains_key(name) {
            let severity = if info.is_promiscuous() {
                Severity::Critical
            } else {
                Severity::Warning
            };

            let message = if info.is_promiscuous() {
                format!(
                    "プロミスキャスモードの新規インターフェースを検知: {} (type={}, flags=0x{:x})",
                    name, info.if_type, info.flags
                )
            } else {
                format!(
                    "新規ネットワークインターフェースを検知: {} (type={}, operstate={}, flags=0x{:x})",
                    name, info.if_type, info.operstate, info.flags
                )
            };

            tracing::warn!(
                interface = %name,
                if_type = %info.if_type,
                operstate = %info.operstate,
                flags = format!("0x{:x}", info.flags),
                "新規ネットワークインターフェースを検知しました"
            );

            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "network_interface_added",
                        severity,
                        "network_interface_monitor",
                        message,
                    )
                    .with_details(format!(
                        "interface={}, type={}, operstate={}, flags=0x{:x}, address={}",
                        name, info.if_type, info.operstate, info.flags, info.address
                    )),
                );
            }
            issues += 1;
        }
    }

    // 削除されたインターフェースを検出
    for (name, old_info) in baseline {
        if !current_map.contains_key(name) {
            tracing::info!(
                interface = %name,
                "ネットワークインターフェースが削除されました"
            );

            if let Some(bus) = event_bus {
                bus.publish(
                    SecurityEvent::new(
                        "network_interface_removed",
                        Severity::Info,
                        "network_interface_monitor",
                        format!(
                            "ネットワークインターフェースが削除されました: {} (type={})",
                            name, old_info.if_type
                        ),
                    )
                    .with_details(format!(
                        "interface={}, type={}, address={}",
                        name, old_info.if_type, old_info.address
                    )),
                );
            }
            issues += 1;
        }
    }

    // 既存インターフェースの変更を検出
    for (name, new_info) in &current_map {
        if let Some(old_info) = baseline.get(name) {
            // プロミスキャスモードの変化チェック
            let old_promisc = old_info.is_promiscuous();
            let new_promisc = new_info.is_promiscuous();

            if !old_promisc && new_promisc {
                tracing::error!(
                    interface = %name,
                    "プロミスキャスモードが有効化されました"
                );

                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "promiscuous_mode_enabled",
                            Severity::Critical,
                            "network_interface_monitor",
                            format!(
                                "プロミスキャスモードが有効化されました: {} — パケットスニッフィングの可能性",
                                name
                            ),
                        )
                        .with_details(format!(
                            "interface={}, old_flags=0x{:x}, new_flags=0x{:x}",
                            name, old_info.flags, new_info.flags
                        )),
                    );
                }
                issues += 1;
            } else if old_promisc && !new_promisc {
                tracing::info!(
                    interface = %name,
                    "プロミスキャスモードが無効化されました"
                );

                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "promiscuous_mode_disabled",
                            Severity::Info,
                            "network_interface_monitor",
                            format!("プロミスキャスモードが無効化されました: {}", name),
                        )
                        .with_details(format!(
                            "interface={}, old_flags=0x{:x}, new_flags=0x{:x}",
                            name, old_info.flags, new_info.flags
                        )),
                    );
                }
            }

            // フラグの変化（プロミスキャス以外）
            let flags_without_promisc_old = old_info.flags & !IFF_PROMISC;
            let flags_without_promisc_new = new_info.flags & !IFF_PROMISC;
            if flags_without_promisc_old != flags_without_promisc_new {
                tracing::warn!(
                    interface = %name,
                    old_flags = format!("0x{:x}", old_info.flags),
                    new_flags = format!("0x{:x}", new_info.flags),
                    "インターフェースフラグが変更されました"
                );

                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "interface_flags_changed",
                            Severity::Warning,
                            "network_interface_monitor",
                            format!(
                                "インターフェースフラグが変更されました: {} (0x{:x} → 0x{:x})",
                                name, old_info.flags, new_info.flags
                            ),
                        )
                        .with_details(format!(
                            "interface={}, old_flags=0x{:x}, new_flags=0x{:x}",
                            name, old_info.flags, new_info.flags
                        )),
                    );
                }
                issues += 1;
            }

            // operstate の変化
            if old_info.operstate != new_info.operstate {
                tracing::info!(
                    interface = %name,
                    old_operstate = %old_info.operstate,
                    new_operstate = %new_info.operstate,
                    "インターフェース動作状態が変化しました"
                );

                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "interface_operstate_changed",
                            Severity::Info,
                            "network_interface_monitor",
                            format!(
                                "インターフェース動作状態が変化しました: {} ({} → {})",
                                name, old_info.operstate, new_info.operstate
                            ),
                        )
                        .with_details(format!(
                            "interface={}, old_operstate={}, new_operstate={}",
                            name, old_info.operstate, new_info.operstate
                        )),
                    );
                }
            }
        }
    }

    issues
}

/// ネットワークインターフェース監視モジュール
///
/// `/sys/class/net/` を定期スキャンし、インターフェースの追加・削除・
/// プロミスキャスモード・フラグ変更を検知する。
pub struct NetworkInterfaceMonitorModule {
    config: NetworkInterfaceMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl NetworkInterfaceMonitorModule {
    /// 新しいネットワークインターフェース監視モジュールを作成する
    pub fn new(config: NetworkInterfaceMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

impl Module for NetworkInterfaceMonitorModule {
    fn name(&self) -> &str {
        "network_interface_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            sys_class_net_path = %self.config.sys_class_net_path.display(),
            ignore_interfaces = ?self.config.ignore_interfaces,
            "ネットワークインターフェース監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        let scan_interval_secs = self.config.scan_interval_secs;
        let sys_class_net_path = self.config.sys_class_net_path.clone();
        let ignore_interfaces = self.config.ignore_interfaces.clone();
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            // 初回スキャンでベースラインを構築
            let interfaces = collect_interfaces(&sys_class_net_path, &ignore_interfaces);
            let mut baseline: BTreeMap<String, InterfaceInfo> = interfaces
                .into_iter()
                .map(|i| (i.name.clone(), i))
                .collect();

            tracing::info!(
                interfaces = baseline.len(),
                "ネットワークインターフェースのベースラインを構築しました"
            );

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("ネットワークインターフェース監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let current = collect_interfaces(&sys_class_net_path, &ignore_interfaces);
                        let issues = compare_and_report(&baseline, &current, &event_bus);

                        if issues == 0 {
                            tracing::debug!("ネットワークインターフェースに変更はありません");
                        }

                        // ベースラインを更新
                        baseline = current.into_iter().map(|i| (i.name.clone(), i)).collect();
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();

        let interfaces = collect_interfaces(
            &self.config.sys_class_net_path,
            &self.config.ignore_interfaces,
        );

        let mut issues_found = 0;

        // プロミスキャスモードのインターフェースを検知
        for iface in &interfaces {
            if iface.is_promiscuous() {
                tracing::error!(
                    interface = %iface.name,
                    flags = format!("0x{:x}", iface.flags),
                    "起動時スキャン: プロミスキャスモードのインターフェースを検知しました"
                );

                if let Some(bus) = &self.event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "promiscuous_mode_detected",
                            Severity::Critical,
                            "network_interface_monitor",
                            format!(
                                "起動時スキャン: プロミスキャスモードのインターフェースを検知: {}",
                                iface.name
                            ),
                        )
                        .with_details(format!(
                            "interface={}, flags=0x{:x}, operstate={}, type={}, address={}",
                            iface.name, iface.flags, iface.operstate, iface.if_type, iface.address
                        )),
                    );
                }
                issues_found += 1;
            }
        }

        // スナップショットデータを構築
        let mut snapshot: BTreeMap<String, String> = BTreeMap::new();
        for iface in &interfaces {
            let key = format!("iface:{}", iface.name);
            snapshot.insert(key, iface.to_snapshot_value());
        }

        let duration = start.elapsed();

        tracing::info!(
            interfaces = interfaces.len(),
            issues = issues_found,
            "起動時スキャン: ネットワークインターフェースをスキャンしました"
        );

        Ok(InitialScanResult {
            items_scanned: interfaces.len(),
            issues_found,
            duration,
            summary: format!(
                "ネットワークインターフェース {}個をスキャン（問題: {}件）",
                interfaces.len(),
                issues_found
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

    /// テスト用の /sys/class/net/ ディレクトリ構造を作成する
    fn create_test_sysfs(interfaces: &[(&str, &str, &str, &str, &str)]) -> TempDir {
        let tmp = TempDir::new().unwrap();
        for (name, flags, operstate, if_type, address) in interfaces {
            let iface_dir = tmp.path().join(name);
            std::fs::create_dir_all(&iface_dir).unwrap();
            std::fs::write(iface_dir.join("flags"), flags).unwrap();
            std::fs::write(iface_dir.join("operstate"), operstate).unwrap();
            std::fs::write(iface_dir.join("type"), if_type).unwrap();
            std::fs::write(iface_dir.join("address"), address).unwrap();
        }
        tmp
    }

    fn make_config(sys_path: &Path) -> NetworkInterfaceMonitorConfig {
        NetworkInterfaceMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            ignore_interfaces: Vec::new(),
            sys_class_net_path: sys_path.to_path_buf(),
        }
    }

    // --- parse_flags ---

    #[test]
    fn test_parse_flags_hex() {
        assert_eq!(parse_flags("0x1003"), 0x1003);
    }

    #[test]
    fn test_parse_flags_with_whitespace() {
        assert_eq!(parse_flags("  0x1003\n"), 0x1003);
    }

    #[test]
    fn test_parse_flags_invalid() {
        assert_eq!(parse_flags("not_a_number"), 0);
    }

    #[test]
    fn test_parse_flags_empty() {
        assert_eq!(parse_flags(""), 0);
    }

    // --- InterfaceInfo ---

    #[test]
    fn test_is_promiscuous() {
        let info = InterfaceInfo {
            name: "eth0".to_string(),
            flags: 0x1103, // IFF_PROMISC (0x100) set
            operstate: "up".to_string(),
            if_type: "1".to_string(),
            address: "00:11:22:33:44:55".to_string(),
        };
        assert!(info.is_promiscuous());
    }

    #[test]
    fn test_is_not_promiscuous() {
        let info = InterfaceInfo {
            name: "eth0".to_string(),
            flags: 0x1003, // IFF_PROMISC not set
            operstate: "up".to_string(),
            if_type: "1".to_string(),
            address: "00:11:22:33:44:55".to_string(),
        };
        assert!(!info.is_promiscuous());
    }

    #[test]
    fn test_to_snapshot_value() {
        let info = InterfaceInfo {
            name: "eth0".to_string(),
            flags: 0x1003,
            operstate: "up".to_string(),
            if_type: "1".to_string(),
            address: "00:11:22:33:44:55".to_string(),
        };
        let value = info.to_snapshot_value();
        assert!(value.contains("flags=0x1003"));
        assert!(value.contains("operstate=up"));
        assert!(value.contains("type=1"));
        assert!(value.contains("address=00:11:22:33:44:55"));
    }

    // --- collect_interfaces ---

    #[test]
    fn test_collect_interfaces() {
        let tmp = create_test_sysfs(&[
            ("eth0", "0x1003", "up", "1", "00:11:22:33:44:55"),
            ("lo", "0x9", "unknown", "772", "00:00:00:00:00:00"),
        ]);

        let interfaces = collect_interfaces(tmp.path(), &[]);
        assert_eq!(interfaces.len(), 2);
        assert_eq!(interfaces[0].name, "eth0");
        assert_eq!(interfaces[1].name, "lo");
    }

    #[test]
    fn test_collect_interfaces_with_ignore() {
        let tmp = create_test_sysfs(&[
            ("eth0", "0x1003", "up", "1", "00:11:22:33:44:55"),
            ("lo", "0x9", "unknown", "772", "00:00:00:00:00:00"),
        ]);

        let ignore = vec!["lo".to_string()];
        let interfaces = collect_interfaces(tmp.path(), &ignore);
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name, "eth0");
    }

    #[test]
    fn test_collect_interfaces_nonexistent_path() {
        let interfaces = collect_interfaces(Path::new("/nonexistent/path"), &[]);
        assert!(interfaces.is_empty());
    }

    #[test]
    fn test_collect_interfaces_missing_attributes() {
        let tmp = TempDir::new().unwrap();
        let iface_dir = tmp.path().join("eth0");
        std::fs::create_dir_all(&iface_dir).unwrap();
        // flags のみ存在、他の属性は欠落
        std::fs::write(iface_dir.join("flags"), "0x1003").unwrap();

        let interfaces = collect_interfaces(tmp.path(), &[]);
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name, "eth0");
        assert_eq!(interfaces[0].flags, 0x1003);
        // 欠落した属性は空文字列になる
        assert_eq!(interfaces[0].operstate, "");
    }

    // --- compare_and_report ---

    #[test]
    fn test_compare_no_changes() {
        let tmp = create_test_sysfs(&[("eth0", "0x1003", "up", "1", "00:11:22:33:44:55")]);
        let interfaces = collect_interfaces(tmp.path(), &[]);
        let baseline: BTreeMap<String, InterfaceInfo> = interfaces
            .iter()
            .map(|i| (i.name.clone(), i.clone()))
            .collect();

        let issues = compare_and_report(&baseline, &interfaces, &None);
        assert_eq!(issues, 0);
    }

    #[test]
    fn test_compare_new_interface() {
        let baseline: BTreeMap<String, InterfaceInfo> = BTreeMap::new();
        let current = vec![InterfaceInfo {
            name: "eth0".to_string(),
            flags: 0x1003,
            operstate: "up".to_string(),
            if_type: "1".to_string(),
            address: "00:11:22:33:44:55".to_string(),
        }];

        let issues = compare_and_report(&baseline, &current, &None);
        assert_eq!(issues, 1);
    }

    #[test]
    fn test_compare_removed_interface() {
        let mut baseline: BTreeMap<String, InterfaceInfo> = BTreeMap::new();
        baseline.insert(
            "eth0".to_string(),
            InterfaceInfo {
                name: "eth0".to_string(),
                flags: 0x1003,
                operstate: "up".to_string(),
                if_type: "1".to_string(),
                address: "00:11:22:33:44:55".to_string(),
            },
        );
        let current: Vec<InterfaceInfo> = Vec::new();

        let issues = compare_and_report(&baseline, &current, &None);
        assert_eq!(issues, 1);
    }

    #[test]
    fn test_compare_promiscuous_mode_enabled() {
        let mut baseline: BTreeMap<String, InterfaceInfo> = BTreeMap::new();
        baseline.insert(
            "eth0".to_string(),
            InterfaceInfo {
                name: "eth0".to_string(),
                flags: 0x1003, // プロミスキャスなし
                operstate: "up".to_string(),
                if_type: "1".to_string(),
                address: "00:11:22:33:44:55".to_string(),
            },
        );

        let current = vec![InterfaceInfo {
            name: "eth0".to_string(),
            flags: 0x1103, // プロミスキャス有効
            operstate: "up".to_string(),
            if_type: "1".to_string(),
            address: "00:11:22:33:44:55".to_string(),
        }];

        let issues = compare_and_report(&baseline, &current, &None);
        assert_eq!(issues, 1);
    }

    #[test]
    fn test_compare_flags_changed_non_promisc() {
        let mut baseline: BTreeMap<String, InterfaceInfo> = BTreeMap::new();
        baseline.insert(
            "eth0".to_string(),
            InterfaceInfo {
                name: "eth0".to_string(),
                flags: 0x1003,
                operstate: "up".to_string(),
                if_type: "1".to_string(),
                address: "00:11:22:33:44:55".to_string(),
            },
        );

        let current = vec![InterfaceInfo {
            name: "eth0".to_string(),
            flags: 0x1043, // フラグ変更（プロミスキャス以外）
            operstate: "up".to_string(),
            if_type: "1".to_string(),
            address: "00:11:22:33:44:55".to_string(),
        }];

        let issues = compare_and_report(&baseline, &current, &None);
        assert_eq!(issues, 1);
    }

    #[test]
    fn test_compare_operstate_changed() {
        let mut baseline: BTreeMap<String, InterfaceInfo> = BTreeMap::new();
        baseline.insert(
            "eth0".to_string(),
            InterfaceInfo {
                name: "eth0".to_string(),
                flags: 0x1003,
                operstate: "up".to_string(),
                if_type: "1".to_string(),
                address: "00:11:22:33:44:55".to_string(),
            },
        );

        let current = vec![InterfaceInfo {
            name: "eth0".to_string(),
            flags: 0x1003,
            operstate: "down".to_string(),
            if_type: "1".to_string(),
            address: "00:11:22:33:44:55".to_string(),
        }];

        // operstate 変化はイベント発行するが issues にはカウントしない
        let issues = compare_and_report(&baseline, &current, &None);
        assert_eq!(issues, 0);
    }

    #[test]
    fn test_compare_new_promiscuous_interface() {
        let baseline: BTreeMap<String, InterfaceInfo> = BTreeMap::new();
        let current = vec![InterfaceInfo {
            name: "evil0".to_string(),
            flags: 0x1103, // プロミスキャス有効な新規インターフェース
            operstate: "up".to_string(),
            if_type: "1".to_string(),
            address: "aa:bb:cc:dd:ee:ff".to_string(),
        }];

        let issues = compare_and_report(&baseline, &current, &None);
        assert_eq!(issues, 1);
    }

    // --- Module lifecycle ---

    #[test]
    fn test_init_zero_interval() {
        let tmp = TempDir::new().unwrap();
        let mut config = make_config(tmp.path());
        config.scan_interval_secs = 0;
        let mut module = NetworkInterfaceMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[test]
    fn test_init_valid() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(tmp.path());
        let mut module = NetworkInterfaceMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(tmp.path());
        let mut module = NetworkInterfaceMonitorModule::new(config, None);
        assert!(module.init().is_ok());
        assert!(module.start().await.is_ok());
        assert!(module.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let tmp = create_test_sysfs(&[
            ("eth0", "0x1003", "up", "1", "00:11:22:33:44:55"),
            ("wlan0", "0x1003", "up", "1", "aa:bb:cc:dd:ee:ff"),
        ]);

        let config = make_config(tmp.path());
        let module = NetworkInterfaceMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 2);
        assert_eq!(result.issues_found, 0);
        assert!(result.snapshot.contains_key("iface:eth0"));
        assert!(result.snapshot.contains_key("iface:wlan0"));
    }

    #[tokio::test]
    async fn test_initial_scan_with_promiscuous() {
        let tmp = create_test_sysfs(&[
            ("eth0", "0x1103", "up", "1", "00:11:22:33:44:55"), // プロミスキャス
        ]);

        let config = make_config(tmp.path());
        let module = NetworkInterfaceMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 1);
        assert_eq!(result.issues_found, 1);
    }

    #[tokio::test]
    async fn test_initial_scan_with_ignore() {
        let tmp = create_test_sysfs(&[
            ("eth0", "0x1003", "up", "1", "00:11:22:33:44:55"),
            ("lo", "0x9", "unknown", "772", "00:00:00:00:00:00"),
        ]);

        let mut config = make_config(tmp.path());
        config.ignore_interfaces = vec!["lo".to_string()];
        let module = NetworkInterfaceMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 1);
        assert!(!result.snapshot.contains_key("iface:lo"));
    }

    #[tokio::test]
    async fn test_initial_scan_empty() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(tmp.path());
        let module = NetworkInterfaceMonitorModule::new(config, None);
        let result = module.initial_scan().await.unwrap();

        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
    }
}
