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

    /// ファイル I/O エラー
    #[error("ファイル I/O エラー: {path}")]
    FileIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// ディレクトリ走査エラー
    #[error("ディレクトリ走査エラー: {path}")]
    DirWalk {
        path: PathBuf,
        #[source]
        source: walkdir::Error,
    },

    /// モジュール設定エラー
    #[error("モジュール設定エラー: {message}")]
    ModuleConfig { message: String },

    /// イベントバスエラー
    #[error("イベントバスエラー: {message}")]
    EventBus { message: String },

    /// アクションルール設定エラー
    #[error("アクションルール設定エラー: {message}")]
    ActionConfig { message: String },

    /// アクション実行エラー
    #[error("アクション実行エラー: {message}")]
    ActionExecution { message: String },

    /// Webhook 送信エラー
    #[error("Webhook 送信エラー: {message}")]
    WebhookSend { message: String },

    /// 設定バリデーションエラー
    #[error("設定バリデーションエラー: {count} 件のエラーが見つかりました")]
    ConfigValidation { count: usize, errors: Vec<String> },
}
