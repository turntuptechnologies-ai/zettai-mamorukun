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
}
