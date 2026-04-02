use crate::error::AppError;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// アプリケーション全体の設定
#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct AppConfig {
    /// 一般設定
    #[serde(default)]
    pub general: GeneralConfig,

    /// デーモン動作設定
    #[serde(default)]
    pub daemon: DaemonConfig,

    /// モジュール設定
    #[serde(default)]
    pub modules: ModulesConfig,

    /// ヘルスチェック設定
    #[serde(default)]
    pub health: HealthConfig,

    /// イベントバス設定
    #[serde(default)]
    pub event_bus: EventBusConfig,

    /// アクションエンジン設定
    #[serde(default)]
    pub actions: ActionConfig,

    /// メトリクス収集設定
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// ステータスサーバー設定
    #[serde(default)]
    pub status: StatusConfig,
}

/// デーモン動作設定
#[derive(Debug, Deserialize, PartialEq)]
pub struct DaemonConfig {
    /// シャットダウンタイムアウト（秒）
    #[serde(default = "DaemonConfig::default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            shutdown_timeout_secs: Self::default_shutdown_timeout_secs(),
        }
    }
}

impl DaemonConfig {
    fn default_shutdown_timeout_secs() -> u64 {
        30
    }
}

/// 一般設定
#[derive(Debug, Deserialize, PartialEq)]
pub struct GeneralConfig {
    /// ログレベル（trace, debug, info, warn, error）
    #[serde(default = "GeneralConfig::default_log_level")]
    pub log_level: String,
}

/// モジュール設定
#[derive(Debug, Default, Deserialize, Clone, PartialEq)]
pub struct ModulesConfig {
    /// ファイル整合性監視モジュールの設定
    #[serde(default)]
    pub file_integrity: FileIntegrityConfig,

    /// プロセス異常検知モジュールの設定
    #[serde(default)]
    pub process_monitor: ProcessMonitorConfig,

    /// カーネルモジュール監視モジュールの設定
    #[serde(default)]
    pub kernel_module: KernelModuleConfig,

    /// at/batch ジョブ監視モジュールの設定
    #[serde(default)]
    pub at_job_monitor: AtJobMonitorConfig,

    /// Cron ジョブ改ざん検知モジュールの設定
    #[serde(default)]
    pub cron_monitor: CronMonitorConfig,

    /// ユーザーアカウント監視モジュールの設定
    #[serde(default)]
    pub user_account: UserAccountConfig,

    /// ログファイル改ざん検知モジュールの設定
    #[serde(default)]
    pub log_tamper: LogTamperConfig,

    /// systemd サービス監視モジュールの設定
    #[serde(default)]
    pub systemd_service: SystemdServiceConfig,

    /// ファイアウォールルール監視モジュールの設定
    #[serde(default)]
    pub firewall_monitor: FirewallMonitorConfig,

    /// DNS設定改ざん検知モジュールの設定
    #[serde(default)]
    pub dns_monitor: DnsMonitorConfig,

    /// SSH公開鍵ファイル監視モジュールの設定
    #[serde(default)]
    pub ssh_key_monitor: SshKeyMonitorConfig,

    /// マウントポイント監視モジュールの設定
    #[serde(default)]
    pub mount_monitor: MountMonitorConfig,

    /// シェル設定ファイル監視モジュールの設定
    #[serde(default)]
    pub shell_config_monitor: ShellConfigMonitorConfig,

    /// 一時ディレクトリ実行ファイル検知モジュールの設定
    #[serde(default)]
    pub tmp_exec_monitor: TmpExecMonitorConfig,

    /// sudoers ファイル監視モジュールの設定
    #[serde(default)]
    pub sudoers_monitor: SudoersMonitorConfig,

    /// SUID/SGID ファイル監視モジュールの設定
    #[serde(default)]
    pub suid_sgid_monitor: SuidSgidMonitorConfig,

    /// SSH ブルートフォース検知モジュールの設定
    #[serde(default)]
    pub ssh_brute_force: SshBruteForceConfig,

    /// パッケージリポジトリ改ざん検知モジュールの設定
    #[serde(default)]
    pub pkg_repo_monitor: PkgRepoMonitorConfig,

    /// 環境変数・LD_PRELOAD 監視モジュールの設定
    #[serde(default)]
    pub ld_preload_monitor: LdPreloadMonitorConfig,

    /// ネットワーク接続監視モジュールの設定
    #[serde(default)]
    pub network_monitor: NetworkMonitorConfig,

    /// PAM 設定監視モジュールの設定
    #[serde(default)]
    pub pam_monitor: PamMonitorConfig,

    /// /etc/security/ 監視モジュールの設定
    #[serde(default)]
    pub security_files_monitor: SecurityFilesMonitorConfig,
}

/// ファイル整合性監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct FileIntegrityConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "FileIntegrityConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default)]
    pub watch_paths: Vec<PathBuf>,
}

impl FileIntegrityConfig {
    fn default_scan_interval_secs() -> u64 {
        300
    }
}

impl Default for FileIntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Vec::new(),
        }
    }
}

/// プロセス異常検知モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct ProcessMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ProcessMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 不審とみなすパスのリスト
    #[serde(default = "ProcessMonitorConfig::default_suspicious_paths")]
    pub suspicious_paths: Vec<PathBuf>,
}

impl ProcessMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_suspicious_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/dev/shm"),
            PathBuf::from("/var/tmp"),
        ]
    }
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            suspicious_paths: Self::default_suspicious_paths(),
        }
    }
}

/// カーネルモジュール監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct KernelModuleConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "KernelModuleConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,
}

impl KernelModuleConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }
}

impl Default for KernelModuleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
        }
    }
}

/// at/batch ジョブ監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct AtJobMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "AtJobMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "AtJobMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl AtJobMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/var/spool/at"),
            PathBuf::from("/var/spool/cron/atjobs"),
            PathBuf::from("/etc/at.allow"),
            PathBuf::from("/etc/at.deny"),
        ]
    }
}

impl Default for AtJobMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// Cron ジョブ改ざん検知モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct CronMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "CronMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "CronMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl CronMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/crontab"),
            PathBuf::from("/etc/cron.d"),
            PathBuf::from("/etc/cron.hourly"),
            PathBuf::from("/etc/cron.daily"),
            PathBuf::from("/etc/cron.weekly"),
            PathBuf::from("/etc/cron.monthly"),
            PathBuf::from("/var/spool/cron/crontabs"),
        ]
    }
}

impl Default for CronMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// ユーザーアカウント監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct UserAccountConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "UserAccountConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// passwd ファイルのパス
    #[serde(default = "UserAccountConfig::default_passwd_path")]
    pub passwd_path: PathBuf,

    /// group ファイルのパス
    #[serde(default = "UserAccountConfig::default_group_path")]
    pub group_path: PathBuf,
}

impl UserAccountConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_passwd_path() -> PathBuf {
        PathBuf::from("/etc/passwd")
    }

    fn default_group_path() -> PathBuf {
        PathBuf::from("/etc/group")
    }
}

impl Default for UserAccountConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            passwd_path: Self::default_passwd_path(),
            group_path: Self::default_group_path(),
        }
    }
}

/// ログファイル改ざん検知モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct LogTamperConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "LogTamperConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "LogTamperConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl LogTamperConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/var/log/syslog"),
            PathBuf::from("/var/log/auth.log"),
            PathBuf::from("/var/log/kern.log"),
            PathBuf::from("/var/log/messages"),
        ]
    }
}

impl Default for LogTamperConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// systemd サービス監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct SystemdServiceConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SystemdServiceConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "SystemdServiceConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl SystemdServiceConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/systemd/system/"),
            PathBuf::from("/usr/lib/systemd/system/"),
            PathBuf::from("/usr/local/lib/systemd/system/"),
        ]
    }
}

impl Default for SystemdServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// DNS設定改ざん検知モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct DnsMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "DnsMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "DnsMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl DnsMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/resolv.conf"),
            PathBuf::from("/etc/hosts"),
        ]
    }
}

impl Default for DnsMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// ファイアウォールルール監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct FirewallMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "FirewallMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "FirewallMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl FirewallMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/proc/net/ip_tables_names"),
            PathBuf::from("/proc/net/ip6_tables_names"),
            PathBuf::from("/proc/net/ip_tables_targets"),
            PathBuf::from("/proc/net/ip_tables_matches"),
            PathBuf::from("/proc/net/ip6_tables_targets"),
            PathBuf::from("/proc/net/ip6_tables_matches"),
        ]
    }
}

impl Default for FirewallMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// SSH公開鍵ファイル監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct SshKeyMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SshKeyMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象の authorized_keys ファイルパスのリスト
    #[serde(default = "SshKeyMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl SshKeyMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![PathBuf::from("/root/.ssh/authorized_keys")]
    }
}

impl Default for SshKeyMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// マウントポイント監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct MountMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "MountMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// マウント情報ファイルのパス
    #[serde(default = "MountMonitorConfig::default_mounts_path")]
    pub mounts_path: PathBuf,
}

impl MountMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        30
    }

    fn default_mounts_path() -> PathBuf {
        PathBuf::from("/proc/mounts")
    }
}

impl Default for MountMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            mounts_path: Self::default_mounts_path(),
        }
    }
}

/// シェル設定ファイル監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct ShellConfigMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "ShellConfigMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象のシェル設定ファイルパスのリスト
    #[serde(default = "ShellConfigMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl ShellConfigMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/profile"),
            PathBuf::from("/etc/bash.bashrc"),
            PathBuf::from("/etc/environment"),
            PathBuf::from("/root/.bashrc"),
            PathBuf::from("/root/.profile"),
        ]
    }
}

impl Default for ShellConfigMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// 一時ディレクトリ実行ファイル検知モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct TmpExecMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "TmpExecMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象ディレクトリのリスト
    #[serde(default = "TmpExecMonitorConfig::default_watch_dirs")]
    pub watch_dirs: Vec<PathBuf>,
}

impl TmpExecMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_watch_dirs() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/dev/shm"),
            PathBuf::from("/var/tmp"),
        ]
    }
}

impl Default for TmpExecMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_dirs: Self::default_watch_dirs(),
        }
    }
}

/// sudoers ファイル監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct SudoersMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SudoersMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト（ファイルまたはディレクトリ）
    #[serde(default = "SudoersMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl SudoersMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/sudoers"),
            PathBuf::from("/etc/sudoers.d"),
        ]
    }
}

impl Default for SudoersMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// PAM 設定監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct PamMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "PamMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト（ファイルまたはディレクトリ）
    #[serde(default = "PamMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl PamMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![PathBuf::from("/etc/pam.d")]
    }
}

impl Default for PamMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// /etc/security/ 監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct SecurityFilesMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SecurityFilesMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト（ファイルまたはディレクトリ）
    #[serde(default = "SecurityFilesMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl SecurityFilesMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/security/limits.conf"),
            PathBuf::from("/etc/security/limits.d"),
            PathBuf::from("/etc/security/access.conf"),
            PathBuf::from("/etc/security/namespace.conf"),
            PathBuf::from("/etc/security/group.conf"),
            PathBuf::from("/etc/security/time.conf"),
            PathBuf::from("/etc/security/pam_env.conf"),
            PathBuf::from("/etc/security/faillock.conf"),
            PathBuf::from("/etc/security/pwquality.conf"),
        ]
    }
}

impl Default for SecurityFilesMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// SUID/SGID ファイル監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct SuidSgidMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SuidSgidMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象ディレクトリのリスト
    #[serde(default = "SuidSgidMonitorConfig::default_watch_dirs")]
    pub watch_dirs: Vec<PathBuf>,
}

impl SuidSgidMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        300
    }

    fn default_watch_dirs() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/usr/local/sbin"),
        ]
    }
}

impl Default for SuidSgidMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_dirs: Self::default_watch_dirs(),
        }
    }
}

/// SSH ブルートフォース検知モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct SshBruteForceConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "SshBruteForceConfig::default_interval_secs")]
    pub interval_secs: u64,

    /// 認証ログファイルのパス
    #[serde(default = "SshBruteForceConfig::default_auth_log_path")]
    pub auth_log_path: PathBuf,

    /// 認証失敗の閾値
    #[serde(default = "SshBruteForceConfig::default_max_failures")]
    pub max_failures: u32,

    /// 時間窓（秒）
    #[serde(default = "SshBruteForceConfig::default_time_window_secs")]
    pub time_window_secs: u64,
}

impl SshBruteForceConfig {
    fn default_interval_secs() -> u64 {
        30
    }

    fn default_auth_log_path() -> PathBuf {
        PathBuf::from("/var/log/auth.log")
    }

    fn default_max_failures() -> u32 {
        5
    }

    fn default_time_window_secs() -> u64 {
        300
    }
}

impl Default for SshBruteForceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: Self::default_interval_secs(),
            auth_log_path: Self::default_auth_log_path(),
            max_failures: Self::default_max_failures(),
            time_window_secs: Self::default_time_window_secs(),
        }
    }
}

/// パッケージリポジトリ改ざん検知モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct PkgRepoMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "PkgRepoMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト（ファイルまたはディレクトリ）
    #[serde(default = "PkgRepoMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl PkgRepoMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        120
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/apt/sources.list"),
            PathBuf::from("/etc/apt/sources.list.d"),
            PathBuf::from("/etc/yum.repos.d"),
        ]
    }
}

impl Default for PkgRepoMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// 環境変数・LD_PRELOAD 監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct LdPreloadMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// スキャン間隔（秒）
    #[serde(default = "LdPreloadMonitorConfig::default_scan_interval_secs")]
    pub scan_interval_secs: u64,

    /// 監視対象パスのリスト
    #[serde(default = "LdPreloadMonitorConfig::default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
}

impl LdPreloadMonitorConfig {
    fn default_scan_interval_secs() -> u64 {
        60
    }

    fn default_watch_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/ld.so.preload"),
            PathBuf::from("/etc/environment"),
            PathBuf::from("/etc/ld.so.conf"),
            PathBuf::from("/etc/ld.so.conf.d"),
        ]
    }
}

impl Default for LdPreloadMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: Self::default_scan_interval_secs(),
            watch_paths: Self::default_watch_paths(),
        }
    }
}

/// ネットワーク接続監視モジュールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct NetworkMonitorConfig {
    /// モジュールの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// 監視間隔（秒）
    #[serde(default = "NetworkMonitorConfig::default_interval_secs")]
    pub interval_secs: u64,

    /// 不審ポートリスト
    #[serde(default = "NetworkMonitorConfig::default_suspicious_ports")]
    pub suspicious_ports: Vec<u16>,

    /// 接続数閾値
    #[serde(default = "NetworkMonitorConfig::default_max_connections")]
    pub max_connections: u32,

    /// IPv6 監視の有効/無効
    #[serde(default = "NetworkMonitorConfig::default_enable_ipv6")]
    pub enable_ipv6: bool,
}

impl NetworkMonitorConfig {
    fn default_interval_secs() -> u64 {
        30
    }

    fn default_suspicious_ports() -> Vec<u16> {
        vec![4444, 5555, 6666, 8888, 1337]
    }

    fn default_max_connections() -> u32 {
        1000
    }

    fn default_enable_ipv6() -> bool {
        true
    }
}

impl Default for NetworkMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: Self::default_interval_secs(),
            suspicious_ports: Self::default_suspicious_ports(),
            max_connections: Self::default_max_connections(),
            enable_ipv6: Self::default_enable_ipv6(),
        }
    }
}

/// アクションエンジン設定
#[derive(Debug, Default, Deserialize, Clone, PartialEq)]
pub struct ActionConfig {
    /// アクションエンジンの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// アクションルールのリスト
    #[serde(default)]
    pub rules: Vec<ActionRuleConfig>,

    /// レートリミット設定（未設定時はレートリミットなし）
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

/// レートリミット設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct RateLimitConfig {
    /// コマンド実行のレート制限
    pub command: Option<BucketConfig>,
    /// Webhook 送信のレート制限
    pub webhook: Option<BucketConfig>,
}

/// トークンバケット設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct BucketConfig {
    /// バケット容量（バースト許容数）
    pub max_tokens: u64,
    /// 補充トークン数
    pub refill_amount: u64,
    /// 補充間隔（秒）
    pub refill_interval_secs: u64,
}

/// アクションルールの設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct ActionRuleConfig {
    /// ルール名
    pub name: String,
    /// Severity フィルタ
    pub severity: Option<String>,
    /// モジュール名フィルタ
    pub module: Option<String>,
    /// アクション種別（"log", "command", "webhook"）
    pub action: String,
    /// 実行コマンド
    pub command: Option<String>,
    /// コマンドタイムアウト（秒）
    #[serde(default = "ActionRuleConfig::default_timeout_secs")]
    pub timeout_secs: u64,
    /// Webhook URL
    pub url: Option<String>,
    /// HTTP メソッド（デフォルト: POST）
    #[serde(default)]
    pub method: Option<String>,
    /// HTTP ヘッダー
    #[serde(default)]
    pub headers: Option<std::collections::HashMap<String, String>>,
    /// ボディテンプレート
    pub body_template: Option<String>,
    /// リトライ回数（デフォルト: 3）
    pub max_retries: Option<u32>,
}

impl ActionRuleConfig {
    fn default_timeout_secs() -> u64 {
        30
    }
}

/// ヘルスチェック設定
#[derive(Debug, Deserialize, PartialEq)]
pub struct HealthConfig {
    /// ハートビートを有効にするか
    #[serde(default = "HealthConfig::default_enabled")]
    pub enabled: bool,

    /// ハートビートのインターバル（秒）
    #[serde(default = "HealthConfig::default_interval")]
    pub heartbeat_interval_secs: u64,
}

impl HealthConfig {
    fn default_enabled() -> bool {
        true
    }

    fn default_interval() -> u64 {
        60
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            heartbeat_interval_secs: Self::default_interval(),
        }
    }
}

/// イベントフィルタリング設定
#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
pub struct EventFilterConfig {
    /// イベントを抑制する正規表現パターンのリスト
    #[serde(default)]
    pub exclude_patterns: Vec<String>,

    /// マッチした場合のみイベントを発行する正規表現パターンのリスト
    /// 空の場合は全イベントを通過させる
    #[serde(default)]
    pub include_patterns: Vec<String>,

    /// 指定した Severity 以上のイベントのみ発行
    #[serde(default)]
    pub min_severity: Option<String>,
}

/// イベントバス設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct EventBusConfig {
    /// イベントバスの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// ブロードキャストチャネルの容量
    #[serde(default = "EventBusConfig::default_channel_capacity")]
    pub channel_capacity: usize,

    /// イベントデバウンス間隔（秒）— 0 でデバウンス無効
    #[serde(default = "EventBusConfig::default_debounce_secs")]
    pub debounce_secs: u64,

    /// モジュールごとのイベントフィルタリング設定
    #[serde(default)]
    pub filters: HashMap<String, EventFilterConfig>,
}

impl EventBusConfig {
    fn default_channel_capacity() -> usize {
        1024
    }

    fn default_debounce_secs() -> u64 {
        30
    }
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            channel_capacity: Self::default_channel_capacity(),
            debounce_secs: Self::default_debounce_secs(),
            filters: HashMap::new(),
        }
    }
}

/// メトリクス収集の設定
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct MetricsConfig {
    /// メトリクス収集の有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// サマリーログ出力インターバル（秒）
    #[serde(default = "MetricsConfig::default_interval_secs")]
    pub interval_secs: u64,
}

impl MetricsConfig {
    fn default_interval_secs() -> u64 {
        60
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: Self::default_interval_secs(),
        }
    }
}

/// ステータスサーバー設定
#[derive(Debug, Deserialize, PartialEq)]
pub struct StatusConfig {
    /// ステータスサーバーの有効/無効
    #[serde(default)]
    pub enabled: bool,

    /// Unix ソケットのパス
    #[serde(default = "StatusConfig::default_socket_path")]
    pub socket_path: String,
}

impl StatusConfig {
    fn default_enabled() -> bool {
        false
    }

    fn default_socket_path() -> String {
        "/var/run/zettai-mamorukun/status.sock".to_string()
    }
}

impl Default for StatusConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            socket_path: Self::default_socket_path(),
        }
    }
}

impl GeneralConfig {
    fn default_log_level() -> String {
        "info".to_string()
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: Self::default_log_level(),
        }
    }
}

impl AppConfig {
    /// 設定ファイルの値を検証する。エラーがあればすべて収集して返す。
    pub fn validate(&self) -> Result<(), AppError> {
        let mut errors = Vec::new();

        // general.log_level の検証
        let valid_log_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_log_levels.contains(&self.general.log_level.as_str()) {
            errors.push(format!(
                "general.log_level: 無効な値 '{}' (有効値: {})",
                self.general.log_level,
                valid_log_levels.join(", ")
            ));
        }

        // health 設定の検証
        if self.health.heartbeat_interval_secs == 0 {
            errors.push(
                "health.heartbeat_interval_secs: 0 より大きい値を指定してください".to_string(),
            );
        }

        // event_bus 設定の検証
        if self.event_bus.channel_capacity == 0 {
            errors.push("event_bus.channel_capacity: 0 より大きい値を指定してください".to_string());
        }

        // metrics 設定の検証
        if self.metrics.enabled && self.metrics.interval_secs == 0 {
            errors.push("metrics.interval_secs: 0 より大きい値を指定してください".to_string());
        }

        // 各モジュールの interval 検証
        Self::validate_interval(
            self.modules.file_integrity.scan_interval_secs,
            "modules.file_integrity.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.process_monitor.scan_interval_secs,
            "modules.process_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.kernel_module.scan_interval_secs,
            "modules.kernel_module.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.at_job_monitor.scan_interval_secs,
            "modules.at_job_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.cron_monitor.scan_interval_secs,
            "modules.cron_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.user_account.scan_interval_secs,
            "modules.user_account.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.log_tamper.scan_interval_secs,
            "modules.log_tamper.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.systemd_service.scan_interval_secs,
            "modules.systemd_service.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.firewall_monitor.scan_interval_secs,
            "modules.firewall_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.dns_monitor.scan_interval_secs,
            "modules.dns_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.ssh_key_monitor.scan_interval_secs,
            "modules.ssh_key_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.mount_monitor.scan_interval_secs,
            "modules.mount_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.shell_config_monitor.scan_interval_secs,
            "modules.shell_config_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.tmp_exec_monitor.scan_interval_secs,
            "modules.tmp_exec_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.sudoers_monitor.scan_interval_secs,
            "modules.sudoers_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.pam_monitor.scan_interval_secs,
            "modules.pam_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.security_files_monitor.scan_interval_secs,
            "modules.security_files_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.suid_sgid_monitor.scan_interval_secs,
            "modules.suid_sgid_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.ssh_brute_force.interval_secs,
            "modules.ssh_brute_force.interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.network_monitor.interval_secs,
            "modules.network_monitor.interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.pkg_repo_monitor.scan_interval_secs,
            "modules.pkg_repo_monitor.scan_interval_secs",
            &mut errors,
        );
        Self::validate_interval(
            self.modules.ld_preload_monitor.scan_interval_secs,
            "modules.ld_preload_monitor.scan_interval_secs",
            &mut errors,
        );

        // network_monitor 固有の検証
        if self.modules.network_monitor.max_connections == 0 {
            errors.push(
                "modules.network_monitor.max_connections: 0 より大きい値を指定してください"
                    .to_string(),
            );
        }

        // ssh_brute_force 固有の検証
        if self.modules.ssh_brute_force.max_failures == 0 {
            errors.push(
                "modules.ssh_brute_force.max_failures: 0 より大きい値を指定してください"
                    .to_string(),
            );
        }
        if self.modules.ssh_brute_force.time_window_secs == 0 {
            errors.push(
                "modules.ssh_brute_force.time_window_secs: 0 より大きい値を指定してください"
                    .to_string(),
            );
        }

        // actions.rules の検証
        let valid_actions = ["log", "command", "webhook"];
        let valid_severities = ["Critical", "High", "Warning", "Info"];
        for (i, rule) in self.actions.rules.iter().enumerate() {
            let prefix = format!("actions.rules[{}] ({})", i, rule.name);

            if !valid_actions.contains(&rule.action.as_str()) {
                errors.push(format!(
                    "{}: 無効なアクション種別 '{}' (有効値: {})",
                    prefix,
                    rule.action,
                    valid_actions.join(", ")
                ));
            }

            if let Some(ref severity) = rule.severity
                && !valid_severities.contains(&severity.as_str())
            {
                errors.push(format!(
                    "{}: 無効な severity '{}' (有効値: {})",
                    prefix,
                    severity,
                    valid_severities.join(", ")
                ));
            }

            if rule.action == "command" && rule.command.is_none() {
                errors.push(format!(
                    "{}: action が 'command' の場合、command フィールドは必須です",
                    prefix
                ));
            }

            if rule.action == "webhook" && rule.url.is_none() {
                errors.push(format!(
                    "{}: action が 'webhook' の場合、url フィールドは必須です",
                    prefix
                ));
            }
        }

        // status 設定の検証
        if self.status.enabled && self.status.socket_path.is_empty() {
            errors.push("status.socket_path: 空文字列は指定できません".to_string());
        }

        // rate_limit の検証
        if let Some(ref rate_limit) = self.actions.rate_limit {
            if let Some(ref cmd) = rate_limit.command {
                Self::validate_bucket_config(cmd, "actions.rate_limit.command", &mut errors);
            }
            if let Some(ref wh) = rate_limit.webhook {
                Self::validate_bucket_config(wh, "actions.rate_limit.webhook", &mut errors);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            let count = errors.len();
            Err(AppError::ConfigValidation { count, errors })
        }
    }

    /// interval 値が 0 でないことを検証するヘルパー
    fn validate_interval(value: u64, field_name: &str, errors: &mut Vec<String>) {
        if value == 0 {
            errors.push(format!("{}: 0 より大きい値を指定してください", field_name));
        }
    }

    /// トークンバケット設定の値を検証するヘルパー
    fn validate_bucket_config(config: &BucketConfig, prefix: &str, errors: &mut Vec<String>) {
        if config.max_tokens == 0 {
            errors.push(format!(
                "{}.max_tokens: 0 より大きい値を指定してください",
                prefix
            ));
        }
        if config.refill_amount == 0 {
            errors.push(format!(
                "{}.refill_amount: 0 より大きい値を指定してください",
                prefix
            ));
        }
        if config.refill_interval_secs == 0 {
            errors.push(format!(
                "{}.refill_interval_secs: 0 より大きい値を指定してください",
                prefix
            ));
        }
    }

    /// 有効なモジュール数をカウントする
    pub fn count_enabled_modules(&self) -> usize {
        let m = &self.modules;
        [
            m.file_integrity.enabled,
            m.process_monitor.enabled,
            m.kernel_module.enabled,
            m.at_job_monitor.enabled,
            m.cron_monitor.enabled,
            m.user_account.enabled,
            m.log_tamper.enabled,
            m.systemd_service.enabled,
            m.firewall_monitor.enabled,
            m.dns_monitor.enabled,
            m.ssh_key_monitor.enabled,
            m.mount_monitor.enabled,
            m.shell_config_monitor.enabled,
            m.tmp_exec_monitor.enabled,
            m.sudoers_monitor.enabled,
            m.pam_monitor.enabled,
            m.security_files_monitor.enabled,
            m.suid_sgid_monitor.enabled,
            m.ssh_brute_force.enabled,
            m.pkg_repo_monitor.enabled,
            m.ld_preload_monitor.enabled,
            m.network_monitor.enabled,
        ]
        .iter()
        .filter(|&&e| e)
        .count()
    }

    /// 設定ファイルを読み込む。ファイルが存在しない場合はデフォルト設定を返す。
    pub fn load(path: &Path) -> Result<Self, AppError> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path).map_err(|e| AppError::ConfigRead {
            path: path.to_path_buf(),
            source: e,
        })?;

        toml::from_str(&content).map_err(|e| AppError::ConfigParse {
            path: path.to_path_buf(),
            source: e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_valid_toml() {
        let toml_str = r#"
[general]
log_level = "debug"

[modules]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.general.log_level, "debug");
    }

    #[test]
    fn test_parse_empty_toml() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert_eq!(config.general.log_level, "info");
    }

    #[test]
    fn test_load_nonexistent_file() {
        let config = AppConfig::load(Path::new("/tmp/nonexistent-zettai-config.toml")).unwrap();
        assert_eq!(config.general.log_level, "info");
    }

    #[test]
    fn test_load_invalid_toml() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "invalid = [[[toml").unwrap();
        let result = AppConfig::load(tmpfile.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_health_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(config.health.enabled);
        assert_eq!(config.health.heartbeat_interval_secs, 60);
    }

    #[test]
    fn test_health_config_custom() {
        let toml_str = r#"
[health]
enabled = false
heartbeat_interval_secs = 30
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.health.enabled);
        assert_eq!(config.health.heartbeat_interval_secs, 30);
    }

    #[test]
    fn test_load_valid_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            r#"
[general]
log_level = "warn"
"#
        )
        .unwrap();
        let config = AppConfig::load(tmpfile.path()).unwrap();
        assert_eq!(config.general.log_level, "warn");
    }

    #[test]
    fn test_cron_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.cron_monitor.enabled);
        assert_eq!(config.modules.cron_monitor.scan_interval_secs, 120);
        assert_eq!(config.modules.cron_monitor.watch_paths.len(), 7);
    }

    #[test]
    fn test_cron_monitor_config_custom() {
        let toml_str = r#"
[modules.cron_monitor]
enabled = true
scan_interval_secs = 60
watch_paths = ["/etc/crontab", "/etc/cron.d"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.cron_monitor.enabled);
        assert_eq!(config.modules.cron_monitor.scan_interval_secs, 60);
        assert_eq!(config.modules.cron_monitor.watch_paths.len(), 2);
    }

    #[test]
    fn test_systemd_service_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.systemd_service.enabled);
        assert_eq!(config.modules.systemd_service.scan_interval_secs, 120);
        assert_eq!(config.modules.systemd_service.watch_paths.len(), 3);
    }

    #[test]
    fn test_systemd_service_config_custom() {
        let toml_str = r#"
[modules.systemd_service]
enabled = true
scan_interval_secs = 60
watch_paths = ["/etc/systemd/system/"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.systemd_service.enabled);
        assert_eq!(config.modules.systemd_service.scan_interval_secs, 60);
        assert_eq!(config.modules.systemd_service.watch_paths.len(), 1);
    }

    #[test]
    fn test_dns_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.dns_monitor.enabled);
        assert_eq!(config.modules.dns_monitor.scan_interval_secs, 30);
        assert_eq!(config.modules.dns_monitor.watch_paths.len(), 2);
    }

    #[test]
    fn test_dns_monitor_config_custom() {
        let toml_str = r#"
[modules.dns_monitor]
enabled = true
scan_interval_secs = 15
watch_paths = ["/etc/resolv.conf"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.dns_monitor.enabled);
        assert_eq!(config.modules.dns_monitor.scan_interval_secs, 15);
        assert_eq!(config.modules.dns_monitor.watch_paths.len(), 1);
    }

    #[test]
    fn test_firewall_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.firewall_monitor.enabled);
        assert_eq!(config.modules.firewall_monitor.scan_interval_secs, 60);
        assert_eq!(config.modules.firewall_monitor.watch_paths.len(), 6);
    }

    #[test]
    fn test_firewall_monitor_config_custom() {
        let toml_str = r#"
[modules.firewall_monitor]
enabled = true
scan_interval_secs = 30
watch_paths = ["/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.firewall_monitor.enabled);
        assert_eq!(config.modules.firewall_monitor.scan_interval_secs, 30);
        assert_eq!(config.modules.firewall_monitor.watch_paths.len(), 2);
    }

    #[test]
    fn test_ssh_key_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.ssh_key_monitor.enabled);
        assert_eq!(config.modules.ssh_key_monitor.scan_interval_secs, 120);
        assert_eq!(config.modules.ssh_key_monitor.watch_paths.len(), 1);
        assert_eq!(
            config.modules.ssh_key_monitor.watch_paths[0],
            PathBuf::from("/root/.ssh/authorized_keys")
        );
    }

    #[test]
    fn test_ssh_key_monitor_config_custom() {
        let toml_str = r#"
[modules.ssh_key_monitor]
enabled = true
scan_interval_secs = 60
watch_paths = ["/root/.ssh/authorized_keys", "/home/admin/.ssh/authorized_keys"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.ssh_key_monitor.enabled);
        assert_eq!(config.modules.ssh_key_monitor.scan_interval_secs, 60);
        assert_eq!(config.modules.ssh_key_monitor.watch_paths.len(), 2);
    }

    #[test]
    fn test_mount_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.mount_monitor.enabled);
        assert_eq!(config.modules.mount_monitor.scan_interval_secs, 30);
        assert_eq!(
            config.modules.mount_monitor.mounts_path,
            PathBuf::from("/proc/mounts")
        );
    }

    #[test]
    fn test_mount_monitor_config_custom() {
        let toml_str = r#"
[modules.mount_monitor]
enabled = true
scan_interval_secs = 15
mounts_path = "/proc/self/mounts"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.mount_monitor.enabled);
        assert_eq!(config.modules.mount_monitor.scan_interval_secs, 15);
        assert_eq!(
            config.modules.mount_monitor.mounts_path,
            PathBuf::from("/proc/self/mounts")
        );
    }

    #[test]
    fn test_tmp_exec_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.tmp_exec_monitor.enabled);
        assert_eq!(config.modules.tmp_exec_monitor.scan_interval_secs, 60);
        assert_eq!(config.modules.tmp_exec_monitor.watch_dirs.len(), 3);
    }

    #[test]
    fn test_tmp_exec_monitor_config_custom() {
        let toml_str = r#"
[modules.tmp_exec_monitor]
enabled = true
scan_interval_secs = 30
watch_dirs = ["/tmp", "/dev/shm"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.tmp_exec_monitor.enabled);
        assert_eq!(config.modules.tmp_exec_monitor.scan_interval_secs, 30);
        assert_eq!(config.modules.tmp_exec_monitor.watch_dirs.len(), 2);
    }

    #[test]
    fn test_shell_config_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.shell_config_monitor.enabled);
        assert_eq!(config.modules.shell_config_monitor.scan_interval_secs, 120);
        assert_eq!(config.modules.shell_config_monitor.watch_paths.len(), 5);
    }

    #[test]
    fn test_shell_config_monitor_config_custom() {
        let toml_str = r#"
[modules.shell_config_monitor]
enabled = true
scan_interval_secs = 60
watch_paths = ["/etc/profile", "/etc/bash.bashrc"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.shell_config_monitor.enabled);
        assert_eq!(config.modules.shell_config_monitor.scan_interval_secs, 60);
        assert_eq!(config.modules.shell_config_monitor.watch_paths.len(), 2);
    }

    #[test]
    fn test_sudoers_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.sudoers_monitor.enabled);
        assert_eq!(config.modules.sudoers_monitor.scan_interval_secs, 120);
        assert_eq!(config.modules.sudoers_monitor.watch_paths.len(), 2);
    }

    #[test]
    fn test_sudoers_monitor_config_custom() {
        let toml_str = r#"
[modules.sudoers_monitor]
enabled = true
scan_interval_secs = 60
watch_paths = ["/etc/sudoers"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.sudoers_monitor.enabled);
        assert_eq!(config.modules.sudoers_monitor.scan_interval_secs, 60);
        assert_eq!(config.modules.sudoers_monitor.watch_paths.len(), 1);
    }

    #[test]
    fn test_suid_sgid_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.suid_sgid_monitor.enabled);
        assert_eq!(config.modules.suid_sgid_monitor.scan_interval_secs, 300);
        assert_eq!(config.modules.suid_sgid_monitor.watch_dirs.len(), 4);
    }

    #[test]
    fn test_suid_sgid_monitor_config_custom() {
        let toml_str = r#"
[modules.suid_sgid_monitor]
enabled = true
scan_interval_secs = 120
watch_dirs = ["/usr/bin", "/usr/sbin"]
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.suid_sgid_monitor.enabled);
        assert_eq!(config.modules.suid_sgid_monitor.scan_interval_secs, 120);
        assert_eq!(config.modules.suid_sgid_monitor.watch_dirs.len(), 2);
    }

    #[test]
    fn test_action_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.actions.enabled);
        assert!(config.actions.rules.is_empty());
    }

    #[test]
    fn test_action_config_custom() {
        let toml_str = r#"
[actions]
enabled = true

[[actions.rules]]
name = "critical_log"
severity = "Critical"
action = "log"

[[actions.rules]]
name = "alert_command"
severity = "Warning"
module = "file_integrity"
action = "command"
command = "/usr/local/bin/alert.sh '{{message}}'"
timeout_secs = 10
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.actions.enabled);
        assert_eq!(config.actions.rules.len(), 2);
        assert_eq!(config.actions.rules[0].name, "critical_log");
        assert_eq!(
            config.actions.rules[0].severity,
            Some("Critical".to_string())
        );
        assert_eq!(config.actions.rules[0].action, "log");
        assert!(config.actions.rules[0].command.is_none());
        assert_eq!(config.actions.rules[0].timeout_secs, 30); // default
        assert_eq!(config.actions.rules[1].name, "alert_command");
        assert_eq!(config.actions.rules[1].timeout_secs, 10);
        assert!(config.actions.rules[1].command.is_some());
    }

    #[test]
    fn test_event_bus_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.event_bus.enabled);
        assert_eq!(config.event_bus.channel_capacity, 1024);
    }

    #[test]
    fn test_event_bus_config_custom() {
        let toml_str = r#"
[event_bus]
enabled = true
channel_capacity = 512
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.event_bus.enabled);
        assert_eq!(config.event_bus.channel_capacity, 512);
    }

    #[test]
    fn test_metrics_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.metrics.enabled);
        assert_eq!(config.metrics.interval_secs, 60);
    }

    #[test]
    fn test_metrics_config_custom() {
        let toml_str = r#"
[metrics]
enabled = true
interval_secs = 300
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.metrics.enabled);
        assert_eq!(config.metrics.interval_secs, 300);
    }

    #[test]
    fn test_network_monitor_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.modules.network_monitor.enabled);
        assert_eq!(config.modules.network_monitor.interval_secs, 30);
        assert_eq!(
            config.modules.network_monitor.suspicious_ports,
            vec![4444, 5555, 6666, 8888, 1337]
        );
        assert_eq!(config.modules.network_monitor.max_connections, 1000);
    }

    #[test]
    fn test_network_monitor_config_custom() {
        let toml_str = r#"
[modules.network_monitor]
enabled = true
interval_secs = 60
suspicious_ports = [1234, 5678]
max_connections = 500
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.modules.network_monitor.enabled);
        assert_eq!(config.modules.network_monitor.interval_secs, 60);
        assert_eq!(
            config.modules.network_monitor.suspicious_ports,
            vec![1234, 5678]
        );
        assert_eq!(config.modules.network_monitor.max_connections, 500);
    }

    #[test]
    fn test_modules_config_partial_eq_detects_change() {
        let config1 = ModulesConfig::default();
        let config2 = ModulesConfig::default();
        assert_eq!(config1, config2);

        let mut config3 = ModulesConfig::default();
        config3.dns_monitor.scan_interval_secs = 999;
        assert_ne!(config1, config3);
    }

    #[test]
    fn test_modules_config_partial_eq_enabled_flag() {
        let config1 = ModulesConfig::default();
        let mut config2 = ModulesConfig::default();
        config2.file_integrity.enabled = true;
        assert_ne!(config1, config2);
    }

    #[test]
    fn test_app_config_partial_eq() {
        let config1 = AppConfig::default();
        let config2 = AppConfig::default();
        assert_eq!(config1, config2);

        let mut config3 = AppConfig::default();
        config3.general.log_level = "debug".to_string();
        assert_ne!(config1, config3);
    }

    #[test]
    fn test_load_invalid_toml_returns_parse_error() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "this is not valid toml {{{{").unwrap();
        let result = AppConfig::load(tmpfile.path());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("設定ファイルのパースに失敗"));
    }

    #[test]
    fn test_validate_default_config_is_valid() {
        let config = AppConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_log_level() {
        let mut config = AppConfig::default();
        config.general.log_level = "verbose".to_string();
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert_eq!(errors.len(), 1);
            assert!(errors[0].contains("general.log_level"));
            assert!(errors[0].contains("verbose"));
        }
    }

    #[test]
    fn test_validate_zero_heartbeat_interval() {
        let mut config = AppConfig::default();
        config.health.heartbeat_interval_secs = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("health.heartbeat_interval_secs"))
            );
        }
    }

    #[test]
    fn test_validate_zero_channel_capacity() {
        let mut config = AppConfig::default();
        config.event_bus.channel_capacity = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("event_bus.channel_capacity"))
            );
        }
    }

    #[test]
    fn test_validate_zero_module_interval() {
        let mut config = AppConfig::default();
        config.modules.file_integrity.scan_interval_secs = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("modules.file_integrity.scan_interval_secs"))
            );
        }
    }

    #[test]
    fn test_validate_invalid_action_type() {
        let mut config = AppConfig::default();
        config.actions.rules.push(ActionRuleConfig {
            name: "test_rule".to_string(),
            severity: None,
            module: None,
            action: "invalid".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        });
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(errors.iter().any(|e| e.contains("無効なアクション種別")));
        }
    }

    #[test]
    fn test_validate_invalid_severity() {
        let mut config = AppConfig::default();
        config.actions.rules.push(ActionRuleConfig {
            name: "test_rule".to_string(),
            severity: Some("Unknown".to_string()),
            module: None,
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        });
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(errors.iter().any(|e| e.contains("無効な severity")));
        }
    }

    #[test]
    fn test_validate_command_action_without_command() {
        let mut config = AppConfig::default();
        config.actions.rules.push(ActionRuleConfig {
            name: "test_rule".to_string(),
            severity: None,
            module: None,
            action: "command".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        });
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("command フィールドは必須"))
            );
        }
    }

    #[test]
    fn test_validate_webhook_action_without_url() {
        let mut config = AppConfig::default();
        config.actions.rules.push(ActionRuleConfig {
            name: "test_rule".to_string(),
            severity: None,
            module: None,
            action: "webhook".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        });
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(errors.iter().any(|e| e.contains("url フィールドは必須")));
        }
    }

    #[test]
    fn test_validate_valid_action_rules() {
        let mut config = AppConfig::default();
        config.actions.rules.push(ActionRuleConfig {
            name: "log_rule".to_string(),
            severity: Some("Critical".to_string()),
            module: None,
            action: "log".to_string(),
            command: None,
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        });
        config.actions.rules.push(ActionRuleConfig {
            name: "cmd_rule".to_string(),
            severity: Some("Warning".to_string()),
            module: None,
            action: "command".to_string(),
            command: Some("/bin/echo test".to_string()),
            timeout_secs: 30,
            url: None,
            method: None,
            headers: None,
            body_template: None,
            max_retries: None,
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rate_limit_zero_values() {
        let mut config = AppConfig::default();
        config.actions.rate_limit = Some(RateLimitConfig {
            command: Some(BucketConfig {
                max_tokens: 0,
                refill_amount: 5,
                refill_interval_secs: 60,
            }),
            webhook: None,
        });
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("actions.rate_limit.command.max_tokens"))
            );
        }
    }

    #[test]
    fn test_validate_multiple_errors() {
        let mut config = AppConfig::default();
        config.general.log_level = "invalid".to_string();
        config.health.heartbeat_interval_secs = 0;
        config.event_bus.channel_capacity = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { count, errors }) = result {
            assert_eq!(count, 3);
            assert_eq!(errors.len(), 3);
        }
    }

    #[test]
    fn test_validate_zero_max_connections() {
        let mut config = AppConfig::default();
        config.modules.network_monitor.max_connections = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("network_monitor.max_connections"))
            );
        }
    }

    #[test]
    fn test_validate_zero_max_failures() {
        let mut config = AppConfig::default();
        config.modules.ssh_brute_force.max_failures = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("ssh_brute_force.max_failures"))
            );
        }
    }

    #[test]
    fn test_count_enabled_modules_none() {
        let config = AppConfig::default();
        assert_eq!(config.count_enabled_modules(), 0);
    }

    #[test]
    fn test_count_enabled_modules_some() {
        let mut config = AppConfig::default();
        config.modules.file_integrity.enabled = true;
        config.modules.dns_monitor.enabled = true;
        config.modules.network_monitor.enabled = true;
        assert_eq!(config.count_enabled_modules(), 3);
    }

    #[test]
    fn test_validate_metrics_zero_interval_when_enabled() {
        let mut config = AppConfig::default();
        config.metrics.enabled = true;
        config.metrics.interval_secs = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(errors.iter().any(|e| e.contains("metrics.interval_secs")));
        }
    }

    #[test]
    fn test_validate_metrics_zero_interval_when_disabled() {
        let mut config = AppConfig::default();
        config.metrics.enabled = false;
        config.metrics.interval_secs = 0;
        // メトリクスが無効なら interval_secs = 0 は許容
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_status_config_defaults() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(!config.status.enabled);
        assert_eq!(
            config.status.socket_path,
            "/var/run/zettai-mamorukun/status.sock"
        );
    }

    #[test]
    fn test_status_config_custom() {
        let toml_str = r#"
[status]
enabled = true
socket_path = "/tmp/custom.sock"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.status.enabled);
        assert_eq!(config.status.socket_path, "/tmp/custom.sock");
    }

    #[test]
    fn test_validate_status_empty_socket_path() {
        let mut config = AppConfig::default();
        config.status.enabled = true;
        config.status.socket_path = String::new();
        let result = config.validate();
        assert!(result.is_err());
        if let Err(AppError::ConfigValidation { errors, .. }) = result {
            assert!(errors.iter().any(|e| e.contains("status.socket_path")));
        }
    }

    #[test]
    fn test_validate_status_disabled_empty_socket_path_ok() {
        let mut config = AppConfig::default();
        config.status.enabled = false;
        config.status.socket_path = String::new();
        // ステータスが無効なら空パスは許容
        assert!(config.validate().is_ok());
    }
}
