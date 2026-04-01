pub mod container_escape;
pub mod cron_monitor;
pub mod dns_monitor;
pub mod file_integrity;
pub mod firewall_monitor;
pub mod kernel_module;
pub mod ld_preload_monitor;
pub mod log_tamper;
pub mod mount_monitor;
pub mod network_monitor;
pub mod pam_monitor;
pub mod pkg_repo_monitor;
pub mod process_monitor;
pub mod shell_config_monitor;
pub mod ssh_brute_force;
pub mod ssh_key_monitor;
pub mod sudoers_monitor;
pub mod suid_sgid_monitor;
pub mod systemd_service;
pub mod tmp_exec_monitor;
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
