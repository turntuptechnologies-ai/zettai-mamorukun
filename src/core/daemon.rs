use crate::config::AppConfig;
use crate::core::health::HealthChecker;
use crate::error::AppError;
use crate::modules::Module;
use crate::modules::cron_monitor::CronMonitorModule;
use crate::modules::file_integrity::FileIntegrityModule;
use crate::modules::kernel_module::KernelModuleMonitor;
use crate::modules::process_monitor::ProcessMonitorModule;
use crate::modules::user_account::UserAccountModule;
use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};

/// デーモンプロセスを管理する
pub struct Daemon {
    config: AppConfig,
}

impl Daemon {
    /// 新しいデーモンインスタンスを作成する
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    /// デーモンを起動し、シグナルを受信するまでブロックする
    pub async fn run(&self) -> Result<(), AppError> {
        let mut sigterm = signal(SignalKind::terminate()).map_err(AppError::SignalHandler)?;
        let mut sighup = signal(SignalKind::hangup()).map_err(AppError::SignalHandler)?;

        let health_checker = HealthChecker::new();
        let health_enabled = self.config.health.enabled;
        let heartbeat_interval = Duration::from_secs(self.config.health.heartbeat_interval_secs);
        let mut heartbeat = tokio::time::interval(heartbeat_interval);
        // 最初の tick は即座に発火するのでスキップ
        heartbeat.tick().await;

        // ファイル整合性監視モジュールの初期化と起動
        let fim_cancel_token = if self.config.modules.file_integrity.enabled {
            let mut fim = FileIntegrityModule::new(self.config.modules.file_integrity.clone());
            fim.init()?;
            let cancel_token = fim.cancel_token();
            fim.start().await?;
            tracing::info!("ファイル整合性監視モジュールを起動しました");
            Some(cancel_token)
        } else {
            None
        };

        // プロセス異常検知モジュールの初期化と起動
        let pm_cancel_token = if self.config.modules.process_monitor.enabled {
            let mut pm = ProcessMonitorModule::new(self.config.modules.process_monitor.clone());
            pm.init()?;
            let cancel_token = pm.cancel_token();
            pm.start().await?;
            tracing::info!("プロセス異常検知モジュールを起動しました");
            Some(cancel_token)
        } else {
            None
        };

        // カーネルモジュール監視モジュールの初期化と起動
        let km_cancel_token = if self.config.modules.kernel_module.enabled {
            let mut km = KernelModuleMonitor::new(self.config.modules.kernel_module.clone());
            km.init()?;
            let cancel_token = km.cancel_token();
            km.start().await?;
            tracing::info!("カーネルモジュール監視モジュールを起動しました");
            Some(cancel_token)
        } else {
            None
        };

        // Cron ジョブ改ざん検知モジュールの初期化と起動
        let cm_cancel_token = if self.config.modules.cron_monitor.enabled {
            let mut cm = CronMonitorModule::new(self.config.modules.cron_monitor.clone());
            cm.init()?;
            let cancel_token = cm.cancel_token();
            cm.start().await?;
            tracing::info!("Cron ジョブ改ざん検知モジュールを起動しました");
            Some(cancel_token)
        } else {
            None
        };

        // ユーザーアカウント監視モジュールの初期化と起動
        let ua_cancel_token = if self.config.modules.user_account.enabled {
            let mut ua = UserAccountModule::new(self.config.modules.user_account.clone());
            ua.init()?;
            let cancel_token = ua.cancel_token();
            ua.start().await?;
            tracing::info!("ユーザーアカウント監視モジュールを起動しました");
            Some(cancel_token)
        } else {
            None
        };

        tracing::info!("デーモンを起動しました");

        if health_enabled {
            tracing::info!(
                interval_secs = self.config.health.heartbeat_interval_secs,
                "ハートビートを有効化しました"
            );
        }

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("SIGINT を受信しました。シャットダウンします...");
                    break;
                }
                _ = sigterm.recv() => {
                    tracing::info!("SIGTERM を受信しました。シャットダウンします...");
                    break;
                }
                _ = sighup.recv() => {
                    tracing::info!("SIGHUP を受信しました。ホットリロードは未実装です");
                }
                _ = heartbeat.tick(), if health_enabled => {
                    let status = health_checker.status();
                    match status.memory_rss_kb {
                        Some(rss_kb) => {
                            let rss_mb = rss_kb as f64 / 1024.0;
                            tracing::info!(
                                uptime_secs = status.uptime_secs,
                                memory_rss_mb = format!("{rss_mb:.1}"),
                                "ハートビート"
                            );
                        }
                        None => {
                            tracing::info!(
                                uptime_secs = status.uptime_secs,
                                "ハートビート（メモリ情報取得不可）"
                            );
                        }
                    }
                }
            }
        }

        // モジュールの停止
        if let Some(cancel_token) = fim_cancel_token {
            cancel_token.cancel();
            tracing::info!("ファイル整合性監視モジュールを停止しました");
        }
        if let Some(cancel_token) = pm_cancel_token {
            cancel_token.cancel();
            tracing::info!("プロセス異常検知モジュールを停止しました");
        }
        if let Some(cancel_token) = km_cancel_token {
            cancel_token.cancel();
            tracing::info!("カーネルモジュール監視モジュールを停止しました");
        }
        if let Some(cancel_token) = cm_cancel_token {
            cancel_token.cancel();
            tracing::info!("Cron ジョブ改ざん検知モジュールを停止しました");
        }
        if let Some(cancel_token) = ua_cancel_token {
            cancel_token.cancel();
            tracing::info!("ユーザーアカウント監視モジュールを停止しました");
        }

        tracing::info!("シャットダウン完了");
        Ok(())
    }
}
