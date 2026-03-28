pub mod file_integrity;

use crate::error::AppError;

/// 防御モジュールが実装すべきトレイト
///
/// 各モジュールはこのトレイトを実装し、レジストリに登録される。
pub trait Module: Send + Sync {
    /// モジュールの名前を返す
    fn name(&self) -> &str;

    /// モジュールを初期化する
    fn init(&mut self) -> Result<(), AppError>;

    /// モジュールを開始する（監視を開始）
    fn start(&mut self) -> impl std::future::Future<Output = Result<(), AppError>> + Send;

    /// モジュールを停止する（グレースフルシャットダウン）
    fn stop(&mut self) -> impl std::future::Future<Output = Result<(), AppError>> + Send;
}
