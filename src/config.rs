use crate::error::AppError;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// アプリケーション全体の設定
#[derive(Debug, Default, Deserialize)]
pub struct AppConfig {
    /// 一般設定
    #[serde(default)]
    pub general: GeneralConfig,

    /// モジュール設定
    #[serde(default)]
    pub modules: ModulesConfig,

    /// ヘルスチェック設定
    #[serde(default)]
    pub health: HealthConfig,
}

/// 一般設定
#[derive(Debug, Deserialize)]
pub struct GeneralConfig {
    /// ログレベル（trace, debug, info, warn, error）
    #[serde(default = "GeneralConfig::default_log_level")]
    pub log_level: String,
}

/// モジュール設定
#[derive(Debug, Default, Deserialize)]
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
}

/// ファイル整合性監視モジュールの設定
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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

/// Cron ジョブ改ざん検知モジュールの設定
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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

/// ヘルスチェック設定
#[derive(Debug, Deserialize)]
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
}
