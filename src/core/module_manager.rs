//! モジュールマネージャー — モジュールのライフサイクルを一括管理する

use crate::config::ModulesConfig;
use crate::core::event::EventBus;
use crate::modules::at_job_monitor::AtJobMonitorModule;
use crate::modules::auditd_monitor::AuditdMonitorModule;
use crate::modules::capabilities_monitor::CapabilitiesMonitorModule;
use crate::modules::cgroup_monitor::CgroupMonitorModule;
use crate::modules::container_namespace::ContainerNamespaceModule;
use crate::modules::coredump_monitor::CoredumpMonitorModule;
use crate::modules::cron_monitor::CronMonitorModule;
use crate::modules::dbus_monitor::DbusMonitorModule;
use crate::modules::dns_monitor::DnsMonitorModule;
use crate::modules::ebpf_monitor::EbpfMonitorModule;
use crate::modules::env_injection_monitor::EnvInjectionMonitorModule;
use crate::modules::fd_monitor::FdMonitorModule;
use crate::modules::file_integrity::FileIntegrityModule;
use crate::modules::firewall_monitor::FirewallMonitorModule;
use crate::modules::inotify_monitor::InotifyMonitorModule;
use crate::modules::kallsyms_monitor::KallsymsMonitorModule;
use crate::modules::kernel_module::KernelModuleMonitor;
use crate::modules::kernel_params::KernelParamsModule;
use crate::modules::ld_preload_monitor::LdPreloadMonitorModule;
use crate::modules::listening_port_monitor::ListeningPortMonitorModule;
use crate::modules::log_tamper::LogTamperModule;
use crate::modules::login_session_monitor::LoginSessionMonitorModule;
use crate::modules::mac_monitor::MacMonitorModule;
use crate::modules::mount_monitor::MountMonitorModule;
use crate::modules::network_interface_monitor::NetworkInterfaceMonitorModule;
use crate::modules::network_monitor::NetworkMonitorModule;
use crate::modules::network_traffic_monitor::NetworkTrafficMonitorModule;
use crate::modules::pam_monitor::PamMonitorModule;
use crate::modules::pkg_repo_monitor::PkgRepoMonitorModule;
use crate::modules::proc_maps_monitor::ProcMapsMonitorModule;
use crate::modules::proc_net_monitor::ProcNetMonitorModule;
use crate::modules::process_exec_monitor::ProcessExecMonitorModule;
use crate::modules::process_monitor::ProcessMonitorModule;
use crate::modules::process_tree_monitor::ProcessTreeMonitorModule;
use crate::modules::ptrace_monitor::PtraceMonitorModule;
use crate::modules::seccomp_monitor::SeccompMonitorModule;
use crate::modules::security_files_monitor::SecurityFilesMonitorModule;
use crate::modules::shell_config_monitor::ShellConfigMonitorModule;
use crate::modules::shm_monitor::ShmMonitorModule;
use crate::modules::ssh_brute_force::SshBruteForceModule;
use crate::modules::ssh_key_monitor::SshKeyMonitorModule;
use crate::modules::sudoers_monitor::SudoersMonitorModule;
use crate::modules::suid_sgid_monitor::SuidSgidMonitorModule;
use crate::modules::systemd_service::SystemdServiceModule;
use crate::modules::systemd_timer_monitor::SystemdTimerMonitorModule;
use crate::modules::tls_cert_monitor::TlsCertMonitorModule;
use crate::modules::tmp_exec_monitor::TmpExecMonitorModule;
use crate::modules::usb_monitor::UsbMonitorModule;
use crate::modules::user_account::UserAccountModule;
use crate::modules::xattr_monitor::XattrMonitorModule;
use crate::modules::{InitialScanResult, Module};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// モジュールレジストリ — 全モジュールの一元管理
///
/// 新しいモジュールを追加する場合、このマクロに1行追加するだけでよい。
/// `start_modules`、`run_scan_only`、`reload` の各関数で自動的に使用される。
macro_rules! for_each_module {
    ($callback:ident ! ( $($prefix:tt)* )) => {
        $callback!($($prefix)* file_integrity, FileIntegrityModule, "ファイル整合性監視モジュール");
        $callback!($($prefix)* process_monitor, ProcessMonitorModule, "プロセス異常検知モジュール");
        $callback!($($prefix)* kernel_module, KernelModuleMonitor, "カーネルモジュール監視モジュール");
        $callback!($($prefix)* auditd_monitor, AuditdMonitorModule, "auditd ログ統合モジュール");
        $callback!($($prefix)* at_job_monitor, AtJobMonitorModule, "at/batch ジョブ監視モジュール");
        $callback!($($prefix)* cron_monitor, CronMonitorModule, "Cron ジョブ改ざん検知モジュール");
        $callback!($($prefix)* log_tamper, LogTamperModule, "ログファイル改ざん検知モジュール");
        $callback!($($prefix)* systemd_service, SystemdServiceModule, "systemd サービス監視モジュール");
        $callback!($($prefix)* systemd_timer_monitor, SystemdTimerMonitorModule, "systemd タイマー監視モジュール");
        $callback!($($prefix)* firewall_monitor, FirewallMonitorModule, "ファイアウォールルール監視モジュール");
        $callback!($($prefix)* dns_monitor, DnsMonitorModule, "DNS設定改ざん検知モジュール");
        $callback!($($prefix)* ssh_key_monitor, SshKeyMonitorModule, "SSH公開鍵ファイル監視モジュール");
        $callback!($($prefix)* shell_config_monitor, ShellConfigMonitorModule, "シェル設定ファイル監視モジュール");
        $callback!($($prefix)* tmp_exec_monitor, TmpExecMonitorModule, "一時ディレクトリ実行ファイル検知モジュール");
        $callback!($($prefix)* sudoers_monitor, SudoersMonitorModule, "sudoers ファイル監視モジュール");
        $callback!($($prefix)* suid_sgid_monitor, SuidSgidMonitorModule, "SUID/SGID ファイル監視モジュール");
        $callback!($($prefix)* mount_monitor, MountMonitorModule, "マウントポイント監視モジュール");
        $callback!($($prefix)* ssh_brute_force, SshBruteForceModule, "SSH ブルートフォース検知モジュール");
        $callback!($($prefix)* pkg_repo_monitor, PkgRepoMonitorModule, "パッケージリポジトリ改ざん検知モジュール");
        $callback!($($prefix)* ld_preload_monitor, LdPreloadMonitorModule, "環境変数・LD_PRELOAD 監視モジュール");
        $callback!($($prefix)* network_monitor, NetworkMonitorModule, "ネットワーク接続監視モジュール");
        $callback!($($prefix)* user_account, UserAccountModule, "ユーザーアカウント監視モジュール");
        $callback!($($prefix)* pam_monitor, PamMonitorModule, "PAM 設定監視モジュール");
        $callback!($($prefix)* security_files_monitor, SecurityFilesMonitorModule, "/etc/security/ 監視モジュール");
        $callback!($($prefix)* mac_monitor, MacMonitorModule, "SELinux / AppArmor 監視モジュール");
        $callback!($($prefix)* capabilities_monitor, CapabilitiesMonitorModule, "capabilities 監視モジュール");
        $callback!($($prefix)* container_namespace, ContainerNamespaceModule, "コンテナ・名前空間検知モジュール");
        $callback!($($prefix)* coredump_monitor, CoredumpMonitorModule, "コアダンプ設定監視モジュール");
        $callback!($($prefix)* ebpf_monitor, EbpfMonitorModule, "eBPF プログラム監視モジュール");
        $callback!($($prefix)* dbus_monitor, DbusMonitorModule, "D-Bus シグナル監視モジュール");
        $callback!($($prefix)* cgroup_monitor, CgroupMonitorModule, "cgroup 監視モジュール");
        $callback!($($prefix)* kernel_params, KernelParamsModule, "カーネルパラメータ監視モジュール");
        $callback!($($prefix)* proc_net_monitor, ProcNetMonitorModule, "/proc/net/ 監視モジュール");
        $callback!($($prefix)* seccomp_monitor, SeccompMonitorModule, "seccomp 監視モジュール");
        $callback!($($prefix)* usb_monitor, UsbMonitorModule, "USB デバイス監視モジュール");
        $callback!($($prefix)* listening_port_monitor, ListeningPortMonitorModule, "リスニングポート監視モジュール");
        $callback!($($prefix)* fd_monitor, FdMonitorModule, "ファイルディスクリプタ監視モジュール");
        $callback!($($prefix)* network_interface_monitor, NetworkInterfaceMonitorModule, "ネットワークインターフェース監視モジュール");
        $callback!($($prefix)* network_traffic_monitor, NetworkTrafficMonitorModule, "ネットワークトラフィック異常検知モジュール");
        $callback!($($prefix)* env_injection_monitor, EnvInjectionMonitorModule, "環境変数インジェクション検知モジュール");
        $callback!($($prefix)* shm_monitor, ShmMonitorModule, "共有メモリ監視モジュール");
        $callback!($($prefix)* process_tree_monitor, ProcessTreeMonitorModule, "プロセスツリー監視モジュール");
        $callback!($($prefix)* xattr_monitor, XattrMonitorModule, "xattr 監視モジュール");
        $callback!($($prefix)* inotify_monitor, InotifyMonitorModule, "inotify 監視モジュール");
        $callback!($($prefix)* process_exec_monitor, ProcessExecMonitorModule, "プロセス起動監視モジュール");
        $callback!($($prefix)* tls_cert_monitor, TlsCertMonitorModule, "TLS 証明書有効期限監視モジュール");
        $callback!($($prefix)* login_session_monitor, LoginSessionMonitorModule, "ログインセッション監視モジュール");
        $callback!($($prefix)* proc_maps_monitor, ProcMapsMonitorModule, "プロセスメモリマップ監視モジュール");
        $callback!($($prefix)* ptrace_monitor, PtraceMonitorModule, "ptrace 検知モジュール");
        $callback!($($prefix)* kallsyms_monitor, KallsymsMonitorModule, "カーネルシンボルテーブル監視モジュール");
    };
}

/// 実行中モジュールの情報
struct RunningModule {
    /// モジュール名
    name: String,
    /// キャンセルトークン（停止用）
    cancel_token: CancellationToken,
}

/// 起動時スキャン全体のレポート
pub struct StartupScanReport {
    /// 各モジュールのスキャン結果
    pub results: Vec<(String, InitialScanResult)>,
    /// スキャン全体にかかった時間
    pub total_duration: Duration,
    /// エラーが発生したモジュール（モジュール名, エラーメッセージ）
    pub errors: Vec<(String, String)>,
}

/// リロード結果
pub struct ReloadResult {
    /// 新規起動されたモジュール名
    pub started: Vec<String>,
    /// 停止されたモジュール名
    pub stopped: Vec<String>,
    /// 再起動されたモジュール名（設定変更）
    pub restarted: Vec<String>,
    /// エラーが発生したモジュール（モジュール名, エラーメッセージ）
    pub errors: Vec<(String, String)>,
}

/// モジュールの一括管理
pub struct ModuleManager {
    running_modules: Vec<RunningModule>,
}

/// 個別モジュールの起動を統一的に扱うマクロ（initial_scan 対応）
macro_rules! start_module {
    ($modules:expr, $config:expr, $event_bus:expr, $scan_enabled:expr, $scan_report:expr, $field:ident, $ModuleType:ty, $label:expr) => {
        if $config.$field.enabled {
            let mut module = <$ModuleType>::new($config.$field.clone(), $event_bus.clone());
            match module.init() {
                Ok(()) => {
                    // 起動時スキャンの実行
                    if $scan_enabled {
                        match module.initial_scan().await {
                            Ok(result) => {
                                tracing::info!(
                                    module = $label,
                                    items_scanned = result.items_scanned,
                                    issues_found = result.issues_found,
                                    duration_ms = result.duration.as_millis() as u64,
                                    summary = %result.summary,
                                    "起動時スキャン完了"
                                );
                                $scan_report.results.push(($label.to_string(), result));
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    concat!($label, "の起動時スキャンに失敗しました")
                                );
                                $scan_report.errors.push(($label.to_string(), e.to_string()));
                            }
                        }
                    }

                    let cancel_token = module.cancel_token();
                    match module.start().await {
                        Ok(()) => {
                            tracing::info!(concat!($label, "を起動しました"));
                            $modules.push(RunningModule {
                                name: $label.to_string(),
                                cancel_token,
                            });
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                concat!($label, "の起動に失敗しました")
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        concat!($label, "の初期化に失敗しました")
                    );
                }
            }
        }
    };
}

/// リロード時のモジュール管理マクロ
macro_rules! reload_module {
    ($result:expr, $running:expr, $new_modules:expr, $old_config:expr, $new_config:expr, $event_bus:expr, $field:ident, $ModuleType:ty, $label:expr) => {{
        let was_enabled = $old_config.$field.enabled;
        let is_enabled = $new_config.$field.enabled;

        match (was_enabled, is_enabled) {
            // 無効→有効: 起動
            (false, true) => {
                let mut module =
                    <$ModuleType>::new($new_config.$field.clone(), $event_bus.clone());
                match module.init() {
                    Ok(()) => match module.start().await {
                        Ok(()) => {
                            tracing::info!(concat!($label, "を起動しました"));
                            $new_modules.push(RunningModule {
                                name: $label.to_string(),
                                cancel_token: module.cancel_token(),
                            });
                            $result.started.push($label.to_string());
                        }
                        Err(e) => {
                            let msg = format!("起動失敗: {}", e);
                            tracing::error!(error = %e, concat!($label, "の起動に失敗しました"));
                            $result.errors.push(($label.to_string(), msg));
                        }
                    },
                    Err(e) => {
                        let msg = format!("初期化失敗: {}", e);
                        tracing::error!(error = %e, concat!($label, "の初期化に失敗しました"));
                        $result.errors.push(($label.to_string(), msg));
                    }
                }
            }
            // 有効→無効: 停止
            (true, false) => {
                // 停止（running_modules から該当を探してキャンセル）
                if let Some(pos) = $running.iter().position(|m| m.name == $label) {
                    let removed = $running.remove(pos);
                    removed.cancel_token.cancel();
                    tracing::info!(concat!($label, "を停止しました"));
                    $result.stopped.push($label.to_string());
                }
            }
            // 有効→有効: 設定変更があれば再起動
            (true, true) => {
                if $old_config.$field != $new_config.$field {
                    // 停止
                    if let Some(pos) = $running.iter().position(|m| m.name == $label) {
                        let removed = $running.remove(pos);
                        removed.cancel_token.cancel();
                    }
                    // 再起動
                    let mut module =
                        <$ModuleType>::new($new_config.$field.clone(), $event_bus.clone());
                    match module.init() {
                        Ok(()) => match module.start().await {
                            Ok(()) => {
                                tracing::info!(concat!($label, "を再起動しました"));
                                $new_modules.push(RunningModule {
                                    name: $label.to_string(),
                                    cancel_token: module.cancel_token(),
                                });
                                $result.restarted.push($label.to_string());
                            }
                            Err(e) => {
                                let msg = format!("再起動失敗: {}", e);
                                tracing::error!(
                                    error = %e,
                                    concat!($label, "の再起動に失敗しました")
                                );
                                $result.errors.push(($label.to_string(), msg));
                            }
                        },
                        Err(e) => {
                            let msg = format!("再初期化失敗: {}", e);
                            tracing::error!(
                                error = %e,
                                concat!($label, "の再初期化に失敗しました")
                            );
                            $result.errors.push(($label.to_string(), msg));
                        }
                    }
                } else {
                    // 設定変更なし: そのまま維持（running_modules に残す）
                    if let Some(pos) = $running.iter().position(|m| m.name == $label) {
                        let kept = $running.remove(pos);
                        $new_modules.push(kept);
                    }
                }
            }
            // 無効→無効: 何もしない
            (false, false) => {}
        }
    }};
}

/// スキャンのみ実行するマクロ（init→initial_scan のみ。start() は呼ばない）
macro_rules! scan_only_module {
    ($config:expr, $scan_report:expr, $field:ident, $ModuleType:ty, $label:expr) => {
        if $config.$field.enabled {
            let event_bus: Option<crate::core::event::EventBus> = None;
            let mut module = <$ModuleType>::new($config.$field.clone(), event_bus);
            match module.init() {
                Ok(()) => match module.initial_scan().await {
                    Ok(result) => {
                        $scan_report.results.push(($label.to_string(), result));
                    }
                    Err(e) => {
                        $scan_report
                            .errors
                            .push(($label.to_string(), e.to_string()));
                    }
                },
                Err(e) => {
                    $scan_report
                        .errors
                        .push(($label.to_string(), format!("初期化失敗: {}", e)));
                }
            }
        }
    };
}

impl ModuleManager {
    /// 設定に基づいてモジュールを起動し、ModuleManager と起動時スキャンレポートを返す
    ///
    /// `startup_scan_enabled` が `true` の場合、各モジュールの `init()` 後に
    /// `initial_scan()` を実行してから `start()` を呼ぶ。
    pub async fn start_modules(
        config: &ModulesConfig,
        event_bus: &Option<EventBus>,
        startup_scan_enabled: bool,
    ) -> (Self, StartupScanReport) {
        let mut modules = Vec::new();
        let scan_start = Instant::now();
        let mut scan_report = StartupScanReport {
            results: Vec::new(),
            total_duration: Duration::default(),
            errors: Vec::new(),
        };

        for_each_module!(start_module!(
            modules,
            config,
            event_bus,
            startup_scan_enabled,
            scan_report,
        ));

        scan_report.total_duration = scan_start.elapsed();

        if startup_scan_enabled && !scan_report.results.is_empty() {
            let total_items: usize = scan_report
                .results
                .iter()
                .map(|(_, r)| r.items_scanned)
                .sum();
            let total_issues: usize = scan_report
                .results
                .iter()
                .map(|(_, r)| r.issues_found)
                .sum();
            tracing::info!(
                modules_scanned = scan_report.results.len(),
                total_items = total_items,
                total_issues = total_issues,
                total_duration_ms = scan_report.total_duration.as_millis() as u64,
                errors = scan_report.errors.len(),
                "起動時セキュリティスキャン完了"
            );
        }

        (
            Self {
                running_modules: modules,
            },
            scan_report,
        )
    }

    /// 実行中モジュール名のリストを取得する
    pub fn running_module_names(&self) -> Vec<String> {
        self.running_modules
            .iter()
            .map(|m| m.name.clone())
            .collect()
    }

    /// 全モジュールを停止する
    pub fn stop_all(&mut self) {
        for module in &self.running_modules {
            module.cancel_token.cancel();
            tracing::info!(module = %module.name, "モジュールを停止しました");
        }
        self.running_modules.clear();
    }

    /// スキャンのみ実行する（デーモン起動なし）
    ///
    /// CLI の scan-diff コマンドで使用する。各モジュールの `init()` → `initial_scan()` のみ実行し、
    /// `start()` は呼ばない。
    pub async fn run_scan_only(config: &ModulesConfig) -> StartupScanReport {
        let scan_start = Instant::now();
        let mut scan_report = StartupScanReport {
            results: Vec::new(),
            total_duration: Duration::default(),
            errors: Vec::new(),
        };

        for_each_module!(scan_only_module!(config, scan_report,));

        scan_report.total_duration = scan_start.elapsed();
        scan_report
    }

    /// 設定差分に基づいてモジュールをリロードする
    ///
    /// - 新規有効化されたモジュールを起動
    /// - 無効化されたモジュールを停止
    /// - 設定が変更されたモジュールを再起動
    /// - 設定変更なしのモジュールはそのまま維持
    pub async fn reload(
        &mut self,
        old_config: &ModulesConfig,
        new_config: &ModulesConfig,
        event_bus: &Option<EventBus>,
    ) -> ReloadResult {
        let mut result = ReloadResult {
            started: Vec::new(),
            stopped: Vec::new(),
            restarted: Vec::new(),
            errors: Vec::new(),
        };

        let mut new_modules = Vec::new();

        for_each_module!(reload_module!(
            result,
            self.running_modules,
            new_modules,
            old_config,
            new_config,
            event_bus,
        ));

        self.running_modules = new_modules;

        // リロード結果のサマリーログ
        if !result.started.is_empty() {
            tracing::info!(modules = ?result.started, "新規起動されたモジュール");
        }
        if !result.stopped.is_empty() {
            tracing::info!(modules = ?result.stopped, "停止されたモジュール");
        }
        if !result.restarted.is_empty() {
            tracing::info!(modules = ?result.restarted, "再起動されたモジュール");
        }
        if !result.errors.is_empty() {
            tracing::error!(errors = ?result.errors, "リロード中にエラーが発生したモジュール");
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_running_module_names_empty() {
        let config = ModulesConfig::default();
        let event_bus = None;
        let (manager, _) = ModuleManager::start_modules(&config, &event_bus, false).await;
        assert!(manager.running_module_names().is_empty());
    }

    #[tokio::test]
    async fn test_running_module_names_with_enabled() {
        let mut config = ModulesConfig::default();
        config.dns_monitor.enabled = true;
        let event_bus = None;
        let (manager, _) = ModuleManager::start_modules(&config, &event_bus, false).await;
        let names = manager.running_module_names();
        assert_eq!(names.len(), 1);
        assert!(names.contains(&"DNS設定改ざん検知モジュール".to_string()));
    }

    #[tokio::test]
    async fn test_start_modules_with_all_disabled() {
        let config = ModulesConfig::default();
        let event_bus = None;
        let (manager, _) = ModuleManager::start_modules(&config, &event_bus, false).await;
        assert!(manager.running_modules.is_empty());
    }

    #[tokio::test]
    async fn test_stop_all_clears_modules() {
        let config = ModulesConfig::default();
        let event_bus = None;
        let (mut manager, _) = ModuleManager::start_modules(&config, &event_bus, false).await;
        manager.stop_all();
        assert!(manager.running_modules.is_empty());
    }

    #[tokio::test]
    async fn test_reload_no_changes() {
        let config = ModulesConfig::default();
        let event_bus = None;
        let (mut manager, _) = ModuleManager::start_modules(&config, &event_bus, false).await;
        let result = manager.reload(&config, &config, &event_bus).await;
        assert!(result.started.is_empty());
        assert!(result.stopped.is_empty());
        assert!(result.restarted.is_empty());
        assert!(result.errors.is_empty());
    }

    #[tokio::test]
    async fn test_reload_enable_module() {
        let old_config = ModulesConfig::default();
        let mut new_config = ModulesConfig::default();
        new_config.dns_monitor.enabled = true;

        let event_bus = None;
        let (mut manager, _) = ModuleManager::start_modules(&old_config, &event_bus, false).await;
        let result = manager.reload(&old_config, &new_config, &event_bus).await;
        assert!(
            result
                .started
                .contains(&"DNS設定改ざん検知モジュール".to_string())
        );
        assert_eq!(manager.running_modules.len(), 1);
    }

    #[tokio::test]
    async fn test_reload_disable_module() {
        let mut old_config = ModulesConfig::default();
        old_config.dns_monitor.enabled = true;
        let new_config = ModulesConfig::default();

        let event_bus = None;
        let (mut manager, _) = ModuleManager::start_modules(&old_config, &event_bus, false).await;
        assert_eq!(manager.running_modules.len(), 1);

        let result = manager.reload(&old_config, &new_config, &event_bus).await;
        assert!(
            result
                .stopped
                .contains(&"DNS設定改ざん検知モジュール".to_string())
        );
        assert!(manager.running_modules.is_empty());
    }

    #[tokio::test]
    async fn test_reload_config_change_restarts_module() {
        let mut old_config = ModulesConfig::default();
        old_config.dns_monitor.enabled = true;
        old_config.dns_monitor.scan_interval_secs = 30;

        let mut new_config = old_config.clone();
        new_config.dns_monitor.scan_interval_secs = 60;

        let event_bus = None;
        let (mut manager, _) = ModuleManager::start_modules(&old_config, &event_bus, false).await;
        let result = manager.reload(&old_config, &new_config, &event_bus).await;
        assert!(
            result
                .restarted
                .contains(&"DNS設定改ざん検知モジュール".to_string())
        );
        assert_eq!(manager.running_modules.len(), 1);
    }

    #[tokio::test]
    async fn test_reload_multiple_modules_enable() {
        let old_config = ModulesConfig::default();
        let mut new_config = ModulesConfig::default();
        new_config.dns_monitor.enabled = true;
        new_config.mount_monitor.enabled = true;
        new_config.cron_monitor.enabled = true;

        let event_bus = None;
        let (mut manager, _) = ModuleManager::start_modules(&old_config, &event_bus, false).await;
        let result = manager.reload(&old_config, &new_config, &event_bus).await;
        assert_eq!(result.started.len(), 3);
        assert!(result.stopped.is_empty());
        assert!(result.restarted.is_empty());
        assert_eq!(manager.running_modules.len(), 3);
    }

    #[tokio::test]
    async fn test_reload_multiple_modules_disable() {
        let mut old_config = ModulesConfig::default();
        old_config.dns_monitor.enabled = true;
        old_config.mount_monitor.enabled = true;
        old_config.cron_monitor.enabled = true;

        let new_config = ModulesConfig::default();

        let event_bus = None;
        let (mut manager, _) = ModuleManager::start_modules(&old_config, &event_bus, false).await;
        assert_eq!(manager.running_modules.len(), 3);

        let result = manager.reload(&old_config, &new_config, &event_bus).await;
        assert_eq!(result.stopped.len(), 3);
        assert!(result.started.is_empty());
        assert!(result.restarted.is_empty());
        assert!(manager.running_modules.is_empty());
    }

    #[tokio::test]
    async fn test_reload_mixed_operations() {
        // dns_monitor: 有効→無効（停止）、mount_monitor: 無効→有効（起動）、cron_monitor: 有効→有効（設定変更→再起動）
        let mut old_config = ModulesConfig::default();
        old_config.dns_monitor.enabled = true;
        old_config.cron_monitor.enabled = true;
        old_config.cron_monitor.scan_interval_secs = 60;

        let mut new_config = ModulesConfig::default();
        new_config.dns_monitor.enabled = false;
        new_config.mount_monitor.enabled = true;
        new_config.cron_monitor.enabled = true;
        new_config.cron_monitor.scan_interval_secs = 120;

        let event_bus = None;
        let (mut manager, _) = ModuleManager::start_modules(&old_config, &event_bus, false).await;
        let result = manager.reload(&old_config, &new_config, &event_bus).await;

        assert_eq!(result.stopped.len(), 1);
        assert!(
            result
                .stopped
                .contains(&"DNS設定改ざん検知モジュール".to_string())
        );
        assert_eq!(result.started.len(), 1);
        assert!(
            result
                .started
                .contains(&"マウントポイント監視モジュール".to_string())
        );
        assert_eq!(result.restarted.len(), 1);
        assert!(
            result
                .restarted
                .contains(&"Cron ジョブ改ざん検知モジュール".to_string())
        );
        assert!(result.errors.is_empty());
        // mount_monitor + cron_monitor が有効
        assert_eq!(manager.running_modules.len(), 2);
    }

    #[tokio::test]
    async fn test_reload_result_empty_on_disabled_to_disabled() {
        // 全モジュール無効→全モジュール無効: 何も起きない
        let config = ModulesConfig::default();
        let event_bus = None;
        let (mut manager, _) = ModuleManager::start_modules(&config, &event_bus, false).await;
        let result = manager.reload(&config, &config, &event_bus).await;
        assert!(result.started.is_empty());
        assert!(result.stopped.is_empty());
        assert!(result.restarted.is_empty());
        assert!(result.errors.is_empty());
        assert!(manager.running_modules.is_empty());
    }

    #[tokio::test]
    async fn test_reload_no_restart_when_config_unchanged() {
        // 有効→有効（設定変更なし）: 再起動されないことを確認
        let mut config = ModulesConfig::default();
        config.dns_monitor.enabled = true;
        config.dns_monitor.scan_interval_secs = 30;

        let event_bus = None;
        let (mut manager, _) = ModuleManager::start_modules(&config, &event_bus, false).await;
        assert_eq!(manager.running_modules.len(), 1);

        let result = manager.reload(&config, &config, &event_bus).await;
        assert!(result.started.is_empty());
        assert!(result.stopped.is_empty());
        assert!(result.restarted.is_empty());
        assert!(result.errors.is_empty());
        assert_eq!(manager.running_modules.len(), 1);
    }

    #[tokio::test]
    async fn test_start_modules_with_startup_scan_disabled() {
        let config = ModulesConfig::default();
        let event_bus = None;
        let (manager, report) = ModuleManager::start_modules(&config, &event_bus, false).await;
        assert!(manager.running_modules.is_empty());
        assert!(report.results.is_empty());
        assert!(report.errors.is_empty());
    }

    #[tokio::test]
    async fn test_start_modules_with_startup_scan_enabled() {
        let mut config = ModulesConfig::default();
        config.dns_monitor.enabled = true;
        let event_bus = None;
        let (manager, report) = ModuleManager::start_modules(&config, &event_bus, true).await;
        assert_eq!(manager.running_modules.len(), 1);
        // DNS モジュールの initial_scan が実行されていること
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].0, "DNS設定改ざん検知モジュール");
        assert!(report.errors.is_empty());
    }

    #[tokio::test]
    async fn test_startup_scan_report_total_duration() {
        let config = ModulesConfig::default();
        let event_bus = None;
        let (_, report) = ModuleManager::start_modules(&config, &event_bus, true).await;
        // total_duration はゼロ以上
        assert!(report.total_duration.as_nanos() >= 0);
    }
}
