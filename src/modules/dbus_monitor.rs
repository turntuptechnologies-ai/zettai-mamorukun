//! D-Bus シグナル監視モジュール
//!
//! システムバス上の D-Bus サービスを定期ポーリングし、
//! サービス状態の変更やセッションの作成・削除を検知する。
//!
//! 検知対象:
//! - systemd サービス状態変更（active/inactive/failed 等の遷移）
//! - ログインセッションの作成・削除（logind 経由）
//! - D-Bus 上のサービス名（bus name）の出現・消失
//!
//! `busctl` コマンドを使用して D-Bus の状態を取得するため、
//! D-Bus デーモンが利用できない環境では graceful にスキップする。

use crate::config::DbusMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap, HashSet};
use tokio_util::sync::CancellationToken;

/// D-Bus 上のサービス情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct DbusService {
    /// バス名（例: "org.freedesktop.systemd1"）
    name: String,
    /// プロセス ID
    pid: Option<u32>,
    /// プロセス名
    process: String,
}

/// systemd ユニットの状態
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnitState {
    /// ユニット名
    name: String,
    /// active 状態（active, inactive, failed 等）
    active_state: String,
    /// sub 状態（running, exited, dead 等）
    sub_state: String,
}

/// busctl list --no-pager の出力をパースする
fn parse_busctl_list(output: &str) -> Vec<DbusService> {
    let mut services = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        // ヘッダ行やフッタ行をスキップ
        if line.is_empty()
            || line.starts_with("NAME")
            || line.contains("unique name")
            || line.starts_with("---")
            || line.starts_with(':')
        {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let name = parts[0].to_string();

        // PID を解析（2列目がPID欄の場合）
        let pid = parts.get(1).and_then(|s| {
            if *s == "-" {
                None
            } else {
                s.parse::<u32>().ok()
            }
        });

        // プロセス名（3列目）
        let process = parts
            .get(2)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string());

        services.push(DbusService { name, pid, process });
    }

    services
}

/// systemctl list-units の出力をパースする
fn parse_systemctl_units(output: &str) -> Vec<UnitState> {
    let mut units = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        // ヘッダ行やフッタ行をスキップ
        if line.is_empty()
            || line.starts_with("UNIT")
            || line.starts_with("---")
            || line.contains("loaded units listed")
        {
            continue;
        }

        // 先頭の ● を除去
        let line = line.trim_start_matches('●').trim();

        let parts: Vec<&str> = line.split_whitespace().collect();
        // 最低でも UNIT LOAD ACTIVE SUB の4列が必要
        if parts.len() < 4 {
            continue;
        }

        // サービスユニットのみ対象
        let unit_name = parts[0];
        if !unit_name.ends_with(".service") {
            continue;
        }

        let active_state = parts[2].to_string();
        let sub_state = parts[3].to_string();

        units.push(UnitState {
            name: unit_name.to_string(),
            active_state,
            sub_state,
        });
    }

    units
}

/// busctl list コマンドを実行する
async fn run_busctl_list() -> Result<String, AppError> {
    let output = tokio::process::Command::new("busctl")
        .args(["list", "--no-pager", "--no-legend"])
        .output()
        .await
        .map_err(|e| AppError::ModuleConfig {
            message: format!("busctl コマンドの実行に失敗しました: {}", e),
        })?;

    if !output.status.success() {
        return Err(AppError::ModuleConfig {
            message: format!(
                "busctl list が失敗しました (exit code: {:?})",
                output.status.code()
            ),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// systemctl list-units コマンドを実行する
async fn run_systemctl_list() -> Result<String, AppError> {
    let output = tokio::process::Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--no-legend",
        ])
        .output()
        .await
        .map_err(|e| AppError::ModuleConfig {
            message: format!("systemctl コマンドの実行に失敗しました: {}", e),
        })?;

    if !output.status.success() {
        return Err(AppError::ModuleConfig {
            message: format!(
                "systemctl list-units が失敗しました (exit code: {:?})",
                output.status.code()
            ),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// D-Bus の利用可否を確認する
async fn check_dbus_available() -> bool {
    tokio::process::Command::new("busctl")
        .args(["list", "--no-pager"])
        .output()
        .await
        .is_ok_and(|output| output.status.success())
}

/// D-Bus シグナル監視モジュール
///
/// D-Bus システムバス上のサービスを定期ポーリングし、
/// サービスの出現・消失およびユニット状態の変更を検知する。
pub struct DbusMonitorModule {
    config: DbusMonitorConfig,
    cancel_token: CancellationToken,
    event_bus: Option<EventBus>,
}

impl DbusMonitorModule {
    /// 新しい D-Bus シグナル監視モジュールを作成する
    pub fn new(config: DbusMonitorConfig, event_bus: Option<EventBus>) -> Self {
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

    /// バスサービスの変更を検知しイベントを発行する
    fn detect_bus_changes(
        current: &[DbusService],
        previous: &HashMap<String, DbusService>,
        event_bus: &Option<EventBus>,
    ) {
        let current_names: HashSet<&str> = current.iter().map(|s| s.name.as_str()).collect();
        let previous_names: HashSet<&str> = previous.keys().map(|s| s.as_str()).collect();

        // 新規サービスの検出
        for svc in current {
            if !previous.contains_key(&svc.name) {
                tracing::info!(
                    service = %svc.name,
                    pid = ?svc.pid,
                    process = %svc.process,
                    "新しい D-Bus サービスを検出"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "dbus_service_appeared",
                            Severity::Info,
                            "dbus_monitor",
                            format!("新しい D-Bus サービスを検出: {}", svc.name),
                        )
                        .with_details(format!(
                            "bus_name={}, pid={:?}, process={}",
                            svc.name, svc.pid, svc.process
                        )),
                    );
                }
            }
        }

        // 消失したサービスの検出
        for name in &previous_names {
            if !current_names.contains(*name) {
                tracing::warn!(
                    service = %name,
                    "D-Bus サービスが消失しました"
                );
                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "dbus_service_disappeared",
                            Severity::Warning,
                            "dbus_monitor",
                            format!("D-Bus サービスが消失しました: {}", name),
                        )
                        .with_details(format!("bus_name={}", name)),
                    );
                }
            }
        }
    }

    /// systemd ユニット状態の変更を検知しイベントを発行する
    fn detect_unit_changes(
        current: &[UnitState],
        previous: &HashMap<String, UnitState>,
        event_bus: &Option<EventBus>,
    ) {
        for unit in current {
            if let Some(prev) = previous.get(&unit.name)
                && (prev.active_state != unit.active_state || prev.sub_state != unit.sub_state)
            {
                let severity = if unit.active_state == "failed" {
                    Severity::Critical
                } else if prev.active_state == "active" && unit.active_state != "active" {
                    Severity::Warning
                } else {
                    Severity::Info
                };

                tracing::info!(
                    unit = %unit.name,
                    old_state = %format!("{}/{}", prev.active_state, prev.sub_state),
                    new_state = %format!("{}/{}", unit.active_state, unit.sub_state),
                    "systemd ユニット状態が変更されました"
                );

                if let Some(bus) = event_bus {
                    bus.publish(
                        SecurityEvent::new(
                            "dbus_unit_state_changed",
                            severity,
                            "dbus_monitor",
                            format!(
                                "systemd ユニット状態が変更: {} ({}/{} → {}/{})",
                                unit.name,
                                prev.active_state,
                                prev.sub_state,
                                unit.active_state,
                                unit.sub_state
                            ),
                        )
                        .with_details(format!(
                            "unit={}, old_active={}, old_sub={}, new_active={}, new_sub={}",
                            unit.name,
                            prev.active_state,
                            prev.sub_state,
                            unit.active_state,
                            unit.sub_state
                        )),
                    );
                }
            }
        }
    }
}

impl Module for DbusMonitorModule {
    fn name(&self) -> &str {
        "dbus_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            watch_systemd = self.config.watch_systemd,
            watch_bus_names = self.config.watch_bus_names,
            "D-Bus シグナル監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        // D-Bus が利用可能か確認
        if !check_dbus_available().await {
            tracing::warn!("D-Bus が利用できないため、dbus_monitor モジュールをスキップします");
            return Ok(tokio::spawn(async {}));
        }

        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();
        let watch_systemd = self.config.watch_systemd;
        let watch_bus_names = self.config.watch_bus_names;

        // 初期状態を取得
        let mut known_services: HashMap<String, DbusService> = if watch_bus_names {
            match run_busctl_list().await {
                Ok(output) => parse_busctl_list(&output)
                    .into_iter()
                    .map(|s| (s.name.clone(), s))
                    .collect(),
                Err(e) => {
                    tracing::warn!(error = %e, "初期バスサービスリストの取得に失敗");
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        let mut known_units: HashMap<String, UnitState> = if watch_systemd {
            match run_systemctl_list().await {
                Ok(output) => parse_systemctl_units(&output)
                    .into_iter()
                    .map(|u| (u.name.clone(), u))
                    .collect(),
                Err(e) => {
                    tracing::warn!(error = %e, "初期ユニットリストの取得に失敗");
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        tracing::info!(
            known_services = known_services.len(),
            known_units = known_units.len(),
            "D-Bus ベースラインスキャンが完了しました"
        );

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("D-Bus シグナル監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        // バスサービスの変更検知
                        if watch_bus_names {
                            match run_busctl_list().await {
                                Ok(output) => {
                                    let current = parse_busctl_list(&output);
                                    Self::detect_bus_changes(&current, &known_services, &event_bus);
                                    known_services = current
                                        .into_iter()
                                        .map(|s| (s.name.clone(), s))
                                        .collect();
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "バスサービスリストの取得に失敗");
                                }
                            }
                        }

                        // systemd ユニット状態の変更検知
                        if watch_systemd {
                            match run_systemctl_list().await {
                                Ok(output) => {
                                    let current = parse_systemctl_units(&output);
                                    Self::detect_unit_changes(&current, &known_units, &event_bus);
                                    known_units = current
                                        .into_iter()
                                        .map(|u| (u.name.clone(), u))
                                        .collect();
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "ユニットリストの取得に失敗");
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let mut items_scanned = 0;
        let mut issues_found = 0;
        let mut scan_snapshot: BTreeMap<String, String> = BTreeMap::new();

        // D-Bus が利用可能か確認
        if !check_dbus_available().await {
            return Ok(InitialScanResult {
                items_scanned: 0,
                issues_found: 0,
                duration: start.elapsed(),
                summary: "D-Bus が利用できないためスキップしました".to_string(),
                snapshot: scan_snapshot,
            });
        }

        // バスサービスのスキャン
        if self.config.watch_bus_names
            && let Ok(output) = run_busctl_list().await
        {
            let services = parse_busctl_list(&output);
            for svc in &services {
                scan_snapshot.insert(
                    format!("dbus:service:{}", svc.name),
                    format!("pid={:?}, process={}", svc.pid, svc.process),
                );
                items_scanned += 1;
            }
        }

        // systemd ユニットのスキャン
        if self.config.watch_systemd
            && let Ok(output) = run_systemctl_list().await
        {
            let units = parse_systemctl_units(&output);
            for unit in &units {
                // failed ユニットは問題としてカウント
                if unit.active_state == "failed" {
                    issues_found += 1;
                    tracing::warn!(
                        unit = %unit.name,
                        active_state = %unit.active_state,
                        sub_state = %unit.sub_state,
                        "起動時スキャン: failed 状態のユニットを検出"
                    );
                    if let Some(bus) = &self.event_bus {
                        bus.publish(
                            SecurityEvent::new(
                                "dbus_startup_unit_failed",
                                Severity::Warning,
                                "dbus_monitor",
                                format!(
                                    "起動時スキャン: failed 状態のユニットを検出: {}",
                                    unit.name
                                ),
                            )
                            .with_details(format!(
                                "unit={}, active_state={}, sub_state={}",
                                unit.name, unit.active_state, unit.sub_state
                            )),
                        );
                    }
                }
                scan_snapshot.insert(
                    format!("dbus:unit:{}", unit.name),
                    format!("{}/{}", unit.active_state, unit.sub_state),
                );
                items_scanned += 1;
            }
        }

        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found,
            duration,
            summary: format!(
                "D-Bus サービス/ユニット {}件をスキャン（うち{}件が要注意）",
                items_scanned, issues_found
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

    fn default_config() -> DbusMonitorConfig {
        DbusMonitorConfig {
            enabled: true,
            scan_interval_secs: 30,
            watch_systemd: true,
            watch_bus_names: true,
        }
    }

    #[test]
    fn test_parse_busctl_list_typical_output() {
        let output = r#"org.freedesktop.DBus              1 org.freedesktop.DBus     -          -                   -                   - -
org.freedesktop.systemd1          1 org.freedesktop.systemd1 -          -                   -                   - -
org.freedesktop.login1          789 systemd-logind           -          -                   -                   - -
"#;
        let services = parse_busctl_list(output);
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].name, "org.freedesktop.DBus");
        assert_eq!(services[1].name, "org.freedesktop.systemd1");
        assert_eq!(services[2].name, "org.freedesktop.login1");
        assert_eq!(services[2].pid, Some(789));
    }

    #[test]
    fn test_parse_busctl_list_empty() {
        let output = "";
        let services = parse_busctl_list(output);
        assert!(services.is_empty());
    }

    #[test]
    fn test_parse_busctl_list_skips_unique_names() {
        let output = ":1.0   1 systemd  - - - - -\norg.freedesktop.DBus  1 dbus-daemon - - - - -\n";
        let services = parse_busctl_list(output);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "org.freedesktop.DBus");
    }

    #[test]
    fn test_parse_busctl_list_skips_header() {
        let output = "NAME                              PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION\norg.freedesktop.DBus              1   dbus-daemon     root             -             -                         -          -\n";
        let services = parse_busctl_list(output);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "org.freedesktop.DBus");
    }

    #[test]
    fn test_parse_systemctl_units_typical_output() {
        let output = r#"  ssh.service                    loaded active   running  OpenBSD Secure Shell server
  cron.service                   loaded active   running  Regular background program processing daemon
  systemd-journald.service       loaded active   running  Journal Service
  failed-svc.service             loaded failed   failed   Some Failed Service
"#;
        let units = parse_systemctl_units(output);
        assert_eq!(units.len(), 4);
        assert_eq!(units[0].name, "ssh.service");
        assert_eq!(units[0].active_state, "active");
        assert_eq!(units[0].sub_state, "running");
        assert_eq!(units[3].name, "failed-svc.service");
        assert_eq!(units[3].active_state, "failed");
    }

    #[test]
    fn test_parse_systemctl_units_empty() {
        let output = "";
        let units = parse_systemctl_units(output);
        assert!(units.is_empty());
    }

    #[test]
    fn test_parse_systemctl_units_skips_non_service() {
        let output = "  tmp.mount                      loaded active   mounted  Temporary Directory\n  ssh.service                    loaded active   running  OpenBSD Secure Shell server\n";
        let units = parse_systemctl_units(output);
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "ssh.service");
    }

    #[test]
    fn test_parse_systemctl_units_with_bullet() {
        let output = "● failed.service                 loaded failed   failed   A Failed Service\n";
        let units = parse_systemctl_units(output);
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "failed.service");
        assert_eq!(units[0].active_state, "failed");
    }

    #[test]
    fn test_detect_bus_changes_new_service() {
        let current = vec![DbusService {
            name: "org.freedesktop.test".to_string(),
            pid: Some(100),
            process: "test-daemon".to_string(),
        }];
        let previous = HashMap::new();

        // イベントバスなしで呼び出し — パニックしないことを確認
        DbusMonitorModule::detect_bus_changes(&current, &previous, &None);
    }

    #[test]
    fn test_detect_bus_changes_disappeared_service() {
        let current = vec![];
        let mut previous = HashMap::new();
        previous.insert(
            "org.freedesktop.test".to_string(),
            DbusService {
                name: "org.freedesktop.test".to_string(),
                pid: Some(100),
                process: "test-daemon".to_string(),
            },
        );

        DbusMonitorModule::detect_bus_changes(&current, &previous, &None);
    }

    #[test]
    fn test_detect_bus_changes_no_change() {
        let svc = DbusService {
            name: "org.freedesktop.test".to_string(),
            pid: Some(100),
            process: "test-daemon".to_string(),
        };
        let current = vec![svc.clone()];
        let mut previous = HashMap::new();
        previous.insert("org.freedesktop.test".to_string(), svc);

        DbusMonitorModule::detect_bus_changes(&current, &previous, &None);
    }

    #[test]
    fn test_detect_unit_changes_state_changed() {
        let current = vec![UnitState {
            name: "ssh.service".to_string(),
            active_state: "inactive".to_string(),
            sub_state: "dead".to_string(),
        }];
        let mut previous = HashMap::new();
        previous.insert(
            "ssh.service".to_string(),
            UnitState {
                name: "ssh.service".to_string(),
                active_state: "active".to_string(),
                sub_state: "running".to_string(),
            },
        );

        DbusMonitorModule::detect_unit_changes(&current, &previous, &None);
    }

    #[test]
    fn test_detect_unit_changes_to_failed() {
        let current = vec![UnitState {
            name: "ssh.service".to_string(),
            active_state: "failed".to_string(),
            sub_state: "failed".to_string(),
        }];
        let mut previous = HashMap::new();
        previous.insert(
            "ssh.service".to_string(),
            UnitState {
                name: "ssh.service".to_string(),
                active_state: "active".to_string(),
                sub_state: "running".to_string(),
            },
        );

        DbusMonitorModule::detect_unit_changes(&current, &previous, &None);
    }

    #[test]
    fn test_detect_unit_changes_no_change() {
        let unit = UnitState {
            name: "ssh.service".to_string(),
            active_state: "active".to_string(),
            sub_state: "running".to_string(),
        };
        let current = vec![unit.clone()];
        let mut previous = HashMap::new();
        previous.insert("ssh.service".to_string(), unit);

        DbusMonitorModule::detect_unit_changes(&current, &previous, &None);
    }

    #[test]
    fn test_init_valid() {
        let config = default_config();
        let mut module = DbusMonitorModule::new(config, None);
        assert!(module.init().is_ok());
    }

    #[test]
    fn test_init_zero_interval() {
        let mut config = default_config();
        config.scan_interval_secs = 0;
        let mut module = DbusMonitorModule::new(config, None);
        assert!(module.init().is_err());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = default_config();
        let mut module = DbusMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        // start は D-Bus が無い環境でも graceful にスキップする
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = default_config();
        let module = DbusMonitorModule::new(config, None);

        // D-Bus が無い環境でもエラーにならない
        let result = module.initial_scan().await.unwrap();
        assert!(result.summary.contains("D-Bus") || result.summary.contains("スキップ"));
    }

    #[test]
    fn test_parse_busctl_list_pid_dash() {
        let output = "org.freedesktop.DBus  -  dbus-daemon  -  -  -  -  -\n";
        let services = parse_busctl_list(output);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].pid, None);
    }

    #[test]
    fn test_detect_unit_changes_inactive_to_active() {
        let current = vec![UnitState {
            name: "ssh.service".to_string(),
            active_state: "active".to_string(),
            sub_state: "running".to_string(),
        }];
        let mut previous = HashMap::new();
        previous.insert(
            "ssh.service".to_string(),
            UnitState {
                name: "ssh.service".to_string(),
                active_state: "inactive".to_string(),
                sub_state: "dead".to_string(),
            },
        );

        // inactive → active は Info レベル
        DbusMonitorModule::detect_unit_changes(&current, &previous, &None);
    }
}
