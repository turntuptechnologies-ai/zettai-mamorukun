pub mod at_job_monitor;
pub mod capabilities_monitor;
pub mod cgroup_monitor;
pub mod container_namespace;
pub mod cron_monitor;
pub mod dns_monitor;
pub mod file_integrity;
pub mod firewall_monitor;
pub mod kernel_module;
pub mod kernel_params;
pub mod ld_preload_monitor;
pub mod log_tamper;
pub mod mac_monitor;
pub mod mount_monitor;
pub mod network_monitor;
pub mod pam_monitor;
pub mod pkg_repo_monitor;
pub mod process_monitor;
pub mod security_files_monitor;
pub mod shell_config_monitor;
pub mod ssh_brute_force;
pub mod ssh_key_monitor;
pub mod sudoers_monitor;
pub mod suid_sgid_monitor;
pub mod systemd_service;
pub mod tmp_exec_monitor;
pub mod user_account;

use crate::error::AppError;
use std::collections::BTreeMap;
use std::time::Duration;

/// 起動時スキャン結果
///
/// 各モジュールの `initial_scan()` が返すスキャン結果を表す。
#[derive(Debug, Default)]
pub struct InitialScanResult {
    /// スキャンしたアイテム数
    pub items_scanned: usize,
    /// 検知された問題の数
    pub issues_found: usize,
    /// スキャンにかかった時間
    pub duration: Duration,
    /// サマリーメッセージ
    pub summary: String,
    /// スナップショットデータ（アイテム識別子 → ハッシュ/状態文字列）
    ///
    /// 永続化して次回起動時の差分検出に使用する。
    /// BTreeMap を使用してキー順序を安定させる。
    pub snapshot: BTreeMap<String, String>,
}

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

    /// 起動時の初期スキャンを実行する
    ///
    /// デフォルト実装は何もしない。各モジュールは必要に応じてオーバーライドし、
    /// 現在のシステム状態をスキャンしてベースラインとして記録する。
    fn initial_scan(
        &self,
    ) -> impl std::future::Future<Output = Result<InitialScanResult, AppError>> + Send {
        async { Ok(InitialScanResult::default()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// デフォルト実装をテストするためのダミーモジュール
    struct DummyModule;

    impl Module for DummyModule {
        fn name(&self) -> &str {
            "dummy"
        }

        fn init(&mut self) -> Result<(), AppError> {
            Ok(())
        }

        async fn start(&mut self) -> Result<(), AppError> {
            Ok(())
        }

        async fn stop(&mut self) -> Result<(), AppError> {
            Ok(())
        }
    }

    #[test]
    fn test_initial_scan_result_default() {
        let result = InitialScanResult::default();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
        assert_eq!(result.duration, Duration::default());
        assert!(result.summary.is_empty());
    }

    #[tokio::test]
    async fn test_module_default_initial_scan() {
        let module = DummyModule;
        let result = module.initial_scan().await.unwrap();
        assert_eq!(result.items_scanned, 0);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.is_empty());
    }
}
