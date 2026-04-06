use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process;
use zettai_mamorukun::config::AppConfig;
use zettai_mamorukun::core::daemon::Daemon;
use zettai_mamorukun::core::event_store;
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
    /// イベントストアの統計サマリーを表示する
    EventStats {
        /// データベースファイルパス（省略時は設定ファイルの値を使用）
        #[arg(long, value_name = "PATH")]
        db: Option<String>,
        /// 統計対象の日数（デフォルト: 7）
        #[arg(long, default_value = "7", value_name = "N")]
        days: u32,
        /// JSON 形式で出力
        #[arg(long)]
        json: bool,
    },
    /// 永続化されたセキュリティイベントを検索する
    SearchEvents {
        /// ソースモジュール名でフィルタ
        #[arg(long, value_name = "NAME")]
        module: Option<String>,
        /// 重要度でフィルタ (INFO, WARNING, CRITICAL)
        #[arg(long, value_name = "LEVEL")]
        severity: Option<String>,
        /// 指定日時以降のイベントを表示 (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
        #[arg(long, value_name = "DATETIME")]
        since: Option<String>,
        /// 指定日時以前のイベントを表示 (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
        #[arg(long, value_name = "DATETIME")]
        until: Option<String>,
        /// イベント種別でフィルタ
        #[arg(long, value_name = "TYPE")]
        event_type: Option<String>,
        /// 表示件数の上限
        #[arg(long, default_value = "100", value_name = "N")]
        limit: u32,
        /// JSON Lines 形式で出力
        #[arg(long)]
        json: bool,
        /// データベースファイルパス（省略時は設定ファイルの値を使用）
        #[arg(long, value_name = "PATH")]
        db: Option<String>,
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

/// イベント検索を実行する
#[allow(clippy::too_many_arguments)]
fn run_search_events(
    config_path: &Path,
    module: &Option<String>,
    severity: &Option<String>,
    since: &Option<String>,
    until: &Option<String>,
    event_type: &Option<String>,
    limit: u32,
    json: bool,
    db: &Option<String>,
) {
    // severity の値を検証
    if let Some(sev) = severity {
        let upper = sev.to_uppercase();
        if upper != "INFO" && upper != "WARNING" && upper != "CRITICAL" {
            eprintln!(
                "エラー: 不正な重要度です: {} (INFO, WARNING, CRITICAL のいずれかを指定してください)",
                sev
            );
            process::exit(1);
        }
    }

    // 日時パース
    let since_ts = since.as_ref().map(|s| {
        event_store::parse_datetime(s).unwrap_or_else(|e| {
            eprintln!("エラー: --since の値が不正です: {}", e);
            process::exit(1);
        })
    });

    let until_ts = until.as_ref().map(|s| {
        event_store::parse_datetime(s).unwrap_or_else(|e| {
            eprintln!("エラー: --until の値が不正です: {}", e);
            process::exit(1);
        })
    });

    // DB パスを決定: --db > 設定ファイル
    let db_path = if let Some(path) = db {
        path.clone()
    } else {
        match AppConfig::load(config_path) {
            Ok(config) => config.event_store.database_path,
            Err(_) => {
                // 設定ファイルが読めない場合はデフォルトパスを使用
                "/var/lib/zettai-mamorukun/events.db".to_string()
            }
        }
    };

    // DB を開く
    let conn = match event_store::open_readonly(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("エラー: {}", e);
            process::exit(1);
        }
    };

    // クエリ実行
    let query = event_store::EventQuery {
        module: module.clone(),
        severity: severity.as_ref().map(|s| s.to_uppercase()),
        since: since_ts,
        until: until_ts,
        event_type: event_type.clone(),
        limit,
    };

    let records = match event_store::query_events(&conn, &query) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("エラー: {}", e);
            process::exit(1);
        }
    };

    if records.is_empty() {
        eprintln!("該当するイベントはありません。");
        return;
    }

    if json {
        print_json(&records);
    } else {
        print_table(&records);
    }

    eprintln!("{} 件のイベントが見つかりました。", records.len());
}

/// JSON Lines 形式でイベントを出力する
fn print_json(records: &[event_store::EventRecord]) {
    for record in records {
        // timestamp を ISO 8601 に変換した構造体を出力
        let json_obj = serde_json::json!({
            "id": record.id,
            "timestamp": event_store::format_timestamp_iso(record.timestamp),
            "severity": record.severity,
            "source_module": record.source_module,
            "event_type": record.event_type,
            "message": record.message,
            "details": record.details,
        });
        // unwrap safety: serde_json::to_string は基本的な型で失敗しない
        println!("{}", serde_json::to_string(&json_obj).unwrap());
    }
}

/// テーブル形式でイベントを出力する
fn print_table(records: &[event_store::EventRecord]) {
    println!(
        "{:<6}| {:<19} | {:<8} | {:<20} | {:<18} | メッセージ",
        "ID", "日時", "重要度", "モジュール", "種別"
    );
    println!(
        "{}|{}|{}|{}|{}|{}",
        "-".repeat(6),
        "-".repeat(21),
        "-".repeat(10),
        "-".repeat(22),
        "-".repeat(20),
        "-".repeat(30)
    );
    for record in records {
        let ts = event_store::format_timestamp(record.timestamp);
        println!(
            "{:<6}| {} | {:<8} | {:<20} | {:<18} | {}",
            record.id, ts, record.severity, record.source_module, record.event_type, record.message
        );
    }
}

/// 数値をカンマ区切りでフォーマットする
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len <= 3 {
        return s;
    }
    let mut result = String::with_capacity(len + (len - 1) / 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(b as char);
    }
    result
}

/// イベント統計を実行する
fn run_event_stats(config_path: &Path, db: &Option<String>, days: u32, json: bool) {
    if days < 1 {
        eprintln!("エラー: --days は 1 以上を指定してください");
        process::exit(1);
    }

    // DB パスを決定: --db > 設定ファイル > デフォルト
    let db_path = if let Some(path) = db {
        path.clone()
    } else {
        match AppConfig::load(config_path) {
            Ok(config) => config.event_store.database_path,
            Err(_) => "/var/lib/zettai-mamorukun/events.db".to_string(),
        }
    };

    // DB を開く
    let conn = match event_store::open_readonly(&db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("エラー: {}", e);
            process::exit(1);
        }
    };

    // 統計クエリ実行
    let stats = match event_store::query_event_stats(&conn, days) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("エラー: {}", e);
            process::exit(1);
        }
    };

    if json {
        let output = serde_json::json!({
            "days": days,
            "period_counts": stats.period_counts,
            "severity_counts": stats.severity_counts,
            "top_modules": stats.top_modules,
            "daily_trend": stats.daily_trend,
        });
        // unwrap safety: serde_json::to_string_pretty は基本的な型で失敗しない
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        print_event_stats(&stats, days);
    }
}

/// イベント統計をテキスト形式で出力する
fn print_event_stats(stats: &event_store::EventStats, days: u32) {
    println!("=== イベント統計サマリー（直近 {} 日間） ===", days);
    println!();

    // 期間別イベント件数
    println!("■ 期間別イベント件数");
    println!(
        "  直近 24 時間: {:>10} 件",
        format_number(stats.period_counts.last_24h)
    );
    println!(
        "  直近  7 日間: {:>10} 件",
        format_number(stats.period_counts.last_7d)
    );
    println!(
        "  直近 30 日間: {:>10} 件",
        format_number(stats.period_counts.last_30d)
    );
    println!();

    // 重要度別
    println!("■ 重要度別（直近 {} 日間）", days);
    println!(
        "  CRITICAL: {:>10} 件",
        format_number(stats.severity_counts.critical)
    );
    println!(
        "  WARNING:  {:>10} 件",
        format_number(stats.severity_counts.warning)
    );
    println!(
        "  INFO:     {:>10} 件",
        format_number(stats.severity_counts.info)
    );
    println!();

    // モジュール別 TOP 10
    println!("■ モジュール別 TOP 10（直近 {} 日間）", days);
    if stats.top_modules.is_empty() {
        println!("  （データなし）");
    } else {
        for (i, mc) in stats.top_modules.iter().enumerate() {
            println!(
                "  {:>2}. {:<24} {:>8} 件",
                i + 1,
                mc.module,
                format_number(mc.count)
            );
        }
    }
    println!();

    // 日次推移
    println!("■ 日次推移（直近 {} 日間）", days);
    if stats.daily_trend.is_empty() {
        println!("  （データなし）");
    } else {
        let max_count = stats.daily_trend.iter().map(|d| d.count).max().unwrap_or(0);
        for dc in &stats.daily_trend {
            let bar = if max_count > 0 && dc.count > 0 {
                let bar_len = ((dc.count as f64 / max_count as f64) * 20.0).ceil() as usize;
                "█".repeat(bar_len)
            } else {
                String::new()
            };
            println!("  {}: {:>8} 件 {}", dc.date, format_number(dc.count), bar);
        }
    }
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
        Some(Commands::EventStats { db, days, json }) => {
            run_event_stats(&cli.config, db, *days, *json);
            return Ok(());
        }
        Some(Commands::SearchEvents {
            module,
            severity,
            since,
            until,
            event_type,
            limit,
            json,
            db,
        }) => {
            run_search_events(
                &cli.config,
                module,
                severity,
                since,
                until,
                event_type,
                *limit,
                *json,
                db,
            );
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
