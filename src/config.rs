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
}
