use crate::error::AppError;
use serde::Deserialize;
use std::path::Path;

/// アプリケーション全体の設定
#[derive(Debug, Default, Deserialize)]
pub struct AppConfig {
    /// 一般設定
    #[serde(default)]
    pub general: GeneralConfig,

    /// モジュール設定
    #[serde(default)]
    pub modules: ModulesConfig,
}

/// 一般設定
#[derive(Debug, Deserialize)]
pub struct GeneralConfig {
    /// ログレベル（trace, debug, info, warn, error）
    #[serde(default = "GeneralConfig::default_log_level")]
    pub log_level: String,
}

/// モジュール設定（将来の拡張用）
#[derive(Debug, Default, Deserialize)]
pub struct ModulesConfig {}

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
