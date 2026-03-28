use std::path::PathBuf;
use thiserror::Error;

/// アプリケーション全体のエラー型
#[derive(Debug, Error)]
pub enum AppError {
    /// 設定ファイルの読み込みに失敗
    #[error("設定ファイルの読み込みに失敗しました: {path}")]
    ConfigRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// 設定ファイルのパースに失敗
    #[error("設定ファイルのパースに失敗しました: {path}")]
    ConfigParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    /// シグナルハンドラの登録に失敗
    #[error("シグナルハンドラの登録に失敗しました")]
    SignalHandler(#[source] std::io::Error),
}
