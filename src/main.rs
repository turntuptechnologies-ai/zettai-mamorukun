use clap::Parser;
use std::path::PathBuf;
use zettai_mamorukun::config::AppConfig;
use zettai_mamorukun::core::daemon::Daemon;

/// サイバー攻撃防御デーモン
#[derive(Parser)]
#[command(name = "zettai-mamorukun", about = "サイバー攻撃防御デーモン")]
struct Cli {
    /// 設定ファイルのパス
    #[arg(short, long, default_value = "/etc/zettai-mamorukun/config.toml")]
    config: PathBuf,
}

fn init_logging(log_level: &str) {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_new(log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    fmt().with_env_filter(filter).with_target(true).init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config = AppConfig::load(&cli.config)?;

    init_logging(&config.general.log_level);

    if !cli.config.exists() {
        tracing::warn!(
            path = %cli.config.display(),
            "設定ファイルが見つかりません。デフォルト設定で起動します"
        );
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "ぜったいまもるくん を起動します"
    );

    let daemon = Daemon::new(config);
    daemon.run().await?;

    Ok(())
}
