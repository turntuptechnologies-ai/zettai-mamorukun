use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process;
use zettai_mamorukun::config::AppConfig;
use zettai_mamorukun::core::daemon::Daemon;
use zettai_mamorukun::core::status;
use zettai_mamorukun::error::AppError;

/// サイバー攻撃防御デーモン
#[derive(Parser)]
#[command(name = "zettai-mamorukun", about = "サイバー攻撃防御デーモン")]
struct Cli {
    /// 設定ファイルのパス（デーモンモード時）
    #[arg(
        short,
        long,
        default_value = "/etc/zettai-mamorukun/config.toml",
        global = true
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// 設定ファイルの構文・値の妥当性をチェックする
    CheckConfig {
        /// チェック対象の設定ファイルパス（省略時は --config の値を使用）
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
        /// デフォルト設定との差分を表示する
        #[arg(long)]
        diff: bool,
    },
    /// デーモンの動作状態を表示する
    Status {
        /// ステータスソケットのパス
        #[arg(long, default_value = "/var/run/zettai-mamorukun/status.sock")]
        socket_path: PathBuf,
    },
    /// 前回のスキャン状態と現在の状態を比較し、差分をレポートする
    ScanDiff {
        /// スキャン状態ファイルのパス（省略時は設定ファイルの値を使用）
        #[arg(long, value_name = "PATH")]
        state_file: Option<PathBuf>,
        /// 特定モジュールのみ表示
        #[arg(long, value_name = "NAME")]
        module: Option<String>,
        /// JSON 形式で出力
        #[arg(long)]
        json: bool,
    },
}

fn init_logging(log_level: &str) {
    use tracing_subscriber::{EnvFilter, fmt};

    // unwrap safety: "info" は有効なフィルタディレクティブであり、EnvFilter::new() はパニックしない
    let filter = EnvFilter::try_new(log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    fmt().with_env_filter(filter).with_target(true).init();
}

/// 設定ファイルをチェックし、結果を表示する
fn run_check_config(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!(
        "設定ファイルをチェックしています: {}",
        config_path.display()
    );

    // ファイル存在チェック
    if !config_path.exists() {
        eprintln!(
            "エラー: 設定ファイルが見つかりません: {}",
            config_path.display()
        );
        process::exit(1);
    }

    // TOML パース
    let config = match AppConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("エラー: {}", e);
            if let AppError::ConfigParse { source, .. } = &e {
                eprintln!("  詳細: {}", source);
            }
            process::exit(1);
        }
    };

    // セマンティックバリデーション
    if let Err(e) = config.validate() {
        if let AppError::ConfigValidation { errors, .. } = &e {
            eprintln!("\n設定バリデーションエラー:");
            for (i, err) in errors.iter().enumerate() {
                eprintln!("  {}. {}", i + 1, err);
            }
            eprintln!("\n{} 件のエラーが見つかりました。", errors.len());
        }
        process::exit(1);
    }

    // 成功時のサマリー出力
    let enabled_modules = config.count_enabled_modules();
    let total_modules = 22;
    let action_rules = config.actions.rules.len();

    eprintln!("\n設定ファイルは有効です。");
    eprintln!("  ログレベル: {}", config.general.log_level);
    eprintln!("  有効モジュール: {}/{}", enabled_modules, total_modules);
    eprintln!(
        "  イベントバス: {}",
        if config.event_bus.enabled {
            "有効"
        } else {
            "無効"
        }
    );
    eprintln!("  アクションルール: {} 件", action_rules);
    eprintln!(
        "  メトリクス収集: {}",
        if config.metrics.enabled {
            "有効"
        } else {
            "無効"
        }
    );
    eprintln!(
        "  ヘルスチェック: {}",
        if config.health.enabled {
            "有効"
        } else {
            "無効"
        }
    );
    eprintln!(
        "  ステータスサーバー: {}",
        if config.status.enabled {
            "有効"
        } else {
            "無効"
        }
    );

    Ok(())
}

/// デフォルト設定との差分を表示する
fn run_check_config_diff(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!(
        "設定ファイルの差分を表示しています: {}",
        config_path.display()
    );

    // ファイル存在チェック
    if !config_path.exists() {
        eprintln!(
            "エラー: 設定ファイルが見つかりません: {}",
            config_path.display()
        );
        process::exit(1);
    }

    // TOML パース
    let config = match AppConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("エラー: {}", e);
            if let AppError::ConfigParse { source, .. } = &e {
                eprintln!("  詳細: {}", source);
            }
            process::exit(1);
        }
    };

    // セマンティックバリデーション
    if let Err(e) = config.validate() {
        if let AppError::ConfigValidation { errors, .. } = &e {
            eprintln!("\n設定バリデーションエラー:");
            for (i, err) in errors.iter().enumerate() {
                eprintln!("  {}. {}", i + 1, err);
            }
            eprintln!("\n{} 件のエラーが見つかりました。", errors.len());
        }
        process::exit(1);
    }

    // デフォルト設定と比較
    let diffs = config.diff_from_default();

    if diffs.is_empty() {
        eprintln!("デフォルト設定との差分はありません。");
    } else {
        // セクションごとにグループ化して表示
        let mut current_section = String::new();
        for (path, old_val, new_val) in &diffs {
            let section = path.rsplitn(2, '.').last().unwrap_or(path);
            if section != current_section {
                if !current_section.is_empty() {
                    println!();
                }
                println!("[{}]", section);
                current_section = section.to_string();
            }
            let field = path.rsplit('.').next().unwrap_or(path);
            println!("  {}: {} → {}", field, old_val, new_val);
        }
        eprintln!("\n{} 件の差分が見つかりました。", diffs.len());
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // サブコマンド処理
    match &cli.command {
        Some(Commands::CheckConfig { path, diff }) => {
            let config_path = path.as_ref().unwrap_or(&cli.config);
            if *diff {
                run_check_config_diff(config_path)?;
            } else {
                run_check_config(config_path)?;
            }
            return Ok(());
        }
        Some(Commands::Status { socket_path }) => {
            match status::query_status(socket_path).await {
                Ok(response) => {
                    status::print_status(&response);
                }
                Err(e) => {
                    eprintln!("エラー: {}", e);
                    process::exit(1);
                }
            }
            return Ok(());
        }
        Some(Commands::ScanDiff {
            state_file,
            module,
            json,
        }) => {
            let config_path_ref = &cli.config;
            let config = match AppConfig::load(config_path_ref) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("エラー: 設定ファイルの読み込みに失敗しました: {}", e);
                    process::exit(2);
                }
            };

            let options = zettai_mamorukun::core::scan_diff::ScanDiffOptions {
                module_filter: module.clone(),
                json_output: *json,
            };

            match zettai_mamorukun::core::scan_diff::run_scan_diff(
                &config,
                state_file.as_deref(),
                &options,
            )
            .await
            {
                Ok(has_diff) => {
                    if has_diff {
                        process::exit(1);
                    }
                    // 差分なし: exit(0)
                }
                Err(e) => {
                    eprintln!("エラー: {}", e);
                    process::exit(2);
                }
            }
            return Ok(());
        }
        None => {}
    }

    // デーモンモード
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

    let mut daemon = Daemon::new(config, cli.config.clone());
    daemon.run().await?;

    Ok(())
}
