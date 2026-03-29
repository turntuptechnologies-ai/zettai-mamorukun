pub mod cron_monitor;
pub mod dns_monitor;
pub mod file_integrity;
pub mod firewall_monitor;
pub mod kernel_module;
pub mod log_tamper;
pub mod process_monitor;
pub mod systemd_service;
pub mod user_account;

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
