use crate::config::AppConfig;
use crate::error::AppError;
use tokio::signal::unix::{SignalKind, signal};

/// デーモンプロセスを管理する
pub struct Daemon {
    _config: AppConfig,
}

impl Daemon {
    /// 新しいデーモンインスタンスを作成する
    pub fn new(config: AppConfig) -> Self {
        Self { _config: config }
    }

    /// デーモンを起動し、シグナルを受信するまでブロックする
    pub async fn run(&self) -> Result<(), AppError> {
        let mut sigterm = signal(SignalKind::terminate()).map_err(AppError::SignalHandler)?;
        let mut sighup = signal(SignalKind::hangup()).map_err(AppError::SignalHandler)?;

        tracing::info!("デーモンを起動しました");

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
            }
        }

        tracing::info!("シャットダウン完了");
        Ok(())
    }
}
