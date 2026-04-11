use clap::{Parser, Subcommand};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process;
use zettai_mamorukun::config::AppConfig;
use zettai_mamorukun::core::daemon::Daemon;
use zettai_mamorukun::core::dashboard;
use zettai_mamorukun::core::event_store;
use zettai_mamorukun::core::event_stream;
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
    /// セキュリティイベントを CSV / JSON ファイルにエクスポートする
    ExportEvents {
        /// 出力フォーマット (csv, json)
        #[arg(long, default_value = "json", value_name = "FORMAT")]
        format: String,
        /// 出力ファイルパス（省略時は stdout）
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
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
        /// 最大件数（省略時は全件）
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
        /// データベースファイルパス（省略時は設定ファイルの値を使用）
        #[arg(long, value_name = "PATH")]
        db: Option<String>,
    },
    /// リアルタイムイベントストリームに接続する
    StreamEvents {
        /// ソケットのパス
        #[arg(long, default_value = "/var/run/zettai-mamorukun/event_stream.sock")]
        socket_path: PathBuf,
        /// 出力フォーマット (json, text)
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// リアルタイム監視ダッシュボードを表示する
    Dashboard {
        /// ステータスソケットのパス
        #[arg(long, default_value = "/var/run/zettai-mamorukun/status.sock")]
        status_socket: PathBuf,
        /// イベントストリームソケットのパス
        #[arg(long, default_value = "/var/run/zettai-mamorukun/event_stream.sock")]
        event_stream_socket: PathBuf,
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

fn init_logging(log_level: &str, journald_enabled: bool) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, Registry, fmt};

    // unwrap safety: "info" は有効なフィルタディレクティブであり、EnvFilter::new() はパニックしない
    let filter = EnvFilter::try_new(log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    let fmt_layer = fmt::layer().with_target(true);

    let journald_layer = if journald_enabled {
        match tracing_journald::layer() {
            Ok(layer) => {
                eprintln!("journald レイヤーを有効化しました");
                Some(layer)
            }
            Err(e) => {
                eprintln!(
                    "警告: journald ソケットに接続できません（{}）。stdout のみでログ出力します",
                    e
                );
                None
            }
        }
    } else {
        None
    };

    Registry::default()
        .with(filter)
        .with(fmt_layer)
        .with(journald_layer)
        .init();
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

/// イベントをエクスポートする
#[allow(clippy::too_many_arguments)]
fn run_export_events(
    config_path: &Path,
    format: &str,
    output: Option<&Path>,
    module: &Option<String>,
    severity: &Option<String>,
    since: &Option<String>,
    until: &Option<String>,
    limit: Option<u32>,
    db: &Option<String>,
) {
    // フォーマットの検証
    let fmt_lower = format.to_lowercase();
    if fmt_lower != "csv" && fmt_lower != "json" {
        eprintln!(
            "エラー: 不正なフォーマットです: {} (csv, json のいずれかを指定してください)",
            format
        );
        process::exit(1);
    }

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

    // DB パスを決定
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

    // クエリ実行
    let query = event_store::EventQuery {
        module: module.clone(),
        severity: severity.as_ref().map(|s| s.to_uppercase()),
        since: since_ts,
        until: until_ts,
        event_type: None,
        limit: limit.unwrap_or(u32::MAX),
    };

    let records = match event_store::query_events(&conn, &query) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("エラー: {}", e);
            process::exit(1);
        }
    };

    // 出力先を決定
    let result = if let Some(path) = output {
        let file = match std::fs::File::create(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "エラー: ファイルを作成できません ({}): {}",
                    path.display(),
                    e
                );
                process::exit(1);
            }
        };
        let mut writer = BufWriter::new(file);
        let res = if fmt_lower == "csv" {
            export_csv(&records, &mut writer)
        } else {
            export_json(&records, &mut writer)
        };
        if let Err(e) = writer.flush() {
            eprintln!("エラー: ファイルの書き込みに失敗しました: {}", e);
            process::exit(1);
        }
        res
    } else {
        let stdout = io::stdout();
        let mut writer = BufWriter::new(stdout.lock());
        let res = if fmt_lower == "csv" {
            export_csv(&records, &mut writer)
        } else {
            export_json(&records, &mut writer)
        };
        if let Err(e) = writer.flush() {
            eprintln!("エラー: stdout への書き込みに失敗しました: {}", e);
            process::exit(1);
        }
        res
    };

    if let Err(e) = result {
        eprintln!("エラー: エクスポートに失敗しました: {}", e);
        process::exit(1);
    }

    eprintln!("{} 件のイベントをエクスポートしました。", records.len());
}

/// JSON Lines 形式でイベントをエクスポートする
fn export_json<W: Write>(records: &[event_store::EventRecord], writer: &mut W) -> io::Result<()> {
    for record in records {
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
        writeln!(writer, "{}", serde_json::to_string(&json_obj).unwrap())?;
    }
    Ok(())
}

/// CSV 形式でイベントをエクスポートする
fn export_csv<W: Write>(records: &[event_store::EventRecord], writer: &mut W) -> io::Result<()> {
    let mut csv_writer = csv::Writer::from_writer(writer);

    // ヘッダー
    csv_writer
        .write_record([
            "timestamp",
            "severity",
            "source_module",
            "event_type",
            "message",
            "details",
        ])
        .map_err(io::Error::other)?;

    // データ行
    for record in records {
        let ts = event_store::format_timestamp_iso(record.timestamp);
        let details = record.details.as_deref().unwrap_or("");
        csv_writer
            .write_record([
                ts.as_str(),
                &record.severity,
                &record.source_module,
                &record.event_type,
                &record.message,
                details,
            ])
            .map_err(io::Error::other)?;
    }

    csv_writer.flush().map_err(io::Error::other)?;

    Ok(())
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
        Some(Commands::ExportEvents {
            format,
            output,
            module,
            severity,
            since,
            until,
            limit,
            db,
        }) => {
            run_export_events(
                &cli.config,
                format,
                output.as_deref(),
                module,
                severity,
                since,
                until,
                *limit,
                db,
            );
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
        Some(Commands::StreamEvents {
            socket_path,
            format,
        }) => {
            match event_stream::stream_events(socket_path, format).await {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("エラー: {}", e);
                    process::exit(1);
                }
            }
            return Ok(());
        }
        Some(Commands::Dashboard {
            status_socket,
            event_stream_socket,
        }) => {
            match dashboard::run_dashboard(status_socket, event_stream_socket).await {
                Ok(()) => {}
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

    init_logging(&config.general.log_level, config.general.journald_enabled);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_records() -> Vec<event_store::EventRecord> {
        vec![
            event_store::EventRecord {
                id: 1,
                timestamp: 1704067200, // 2024-01-01T00:00:00Z
                severity: "WARNING".to_string(),
                source_module: "file_integrity".to_string(),
                event_type: "file_modified".to_string(),
                message: "ファイルが変更されました".to_string(),
                details: Some("/etc/passwd".to_string()),
            },
            event_store::EventRecord {
                id: 2,
                timestamp: 1704153600, // 2024-01-02T00:00:00Z
                severity: "CRITICAL".to_string(),
                source_module: "ssh_brute_force".to_string(),
                event_type: "brute_force_detected".to_string(),
                message: "SSH ブルートフォース攻撃を検知".to_string(),
                details: None,
            },
        ]
    }

    #[test]
    fn test_export_json_basic() {
        let records = make_test_records();
        let mut buf = Vec::new();
        export_json(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        // 各行が有効な JSON かパース検証
        let v1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v1["severity"], "WARNING");
        assert_eq!(v1["source_module"], "file_integrity");
        assert_eq!(v1["details"], "/etc/passwd");

        let v2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(v2["severity"], "CRITICAL");
        assert!(v2["details"].is_null());
    }

    #[test]
    fn test_export_json_empty() {
        let records: Vec<event_store::EventRecord> = vec![];
        let mut buf = Vec::new();
        export_json(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "");
    }

    #[test]
    fn test_export_json_timestamp_format() {
        let records = make_test_records();
        let mut buf = Vec::new();
        export_json(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(output.lines().next().unwrap()).unwrap();
        let ts = v["timestamp"].as_str().unwrap();
        assert!(ts.ends_with('Z'), "timestamp should be ISO 8601 UTC");
        assert!(ts.contains('T'), "timestamp should contain 'T' separator");
    }

    #[test]
    fn test_export_csv_basic() {
        let records = make_test_records();
        let mut buf = Vec::new();
        export_csv(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 data rows

        // ヘッダー検証
        assert_eq!(
            lines[0],
            "timestamp,severity,source_module,event_type,message,details"
        );

        // データ行のフィールド数を検証
        let mut rdr = csv::ReaderBuilder::new().from_reader(output.as_bytes());
        let mut count = 0;
        for result in rdr.records() {
            let record = result.unwrap();
            assert_eq!(record.len(), 6);
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn test_export_csv_empty() {
        let records: Vec<event_store::EventRecord> = vec![];
        let mut buf = Vec::new();
        export_csv(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 1); // header only
    }

    #[test]
    fn test_export_csv_details_none() {
        let records = make_test_records();
        let mut buf = Vec::new();
        export_csv(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let mut rdr = csv::ReaderBuilder::new().from_reader(output.as_bytes());
        let mut rows: Vec<csv::StringRecord> = Vec::new();
        for result in rdr.records() {
            rows.push(result.unwrap());
        }

        // 2 行目の details は None → 空文字列
        assert_eq!(&rows[1][5], "");
    }

    #[test]
    fn test_export_csv_special_characters() {
        let records = vec![event_store::EventRecord {
            id: 1,
            timestamp: 1704067200,
            severity: "INFO".to_string(),
            source_module: "test_module".to_string(),
            event_type: "test".to_string(),
            message: "カンマ,を含む\"メッセージ\"\n改行も".to_string(),
            details: Some("details with, commas".to_string()),
        }];
        let mut buf = Vec::new();
        export_csv(&records, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // CSV として再パース可能であることを検証
        let mut rdr = csv::ReaderBuilder::new().from_reader(output.as_bytes());
        let record = rdr.records().next().unwrap().unwrap();
        assert!(record[4].contains("カンマ,を含む"));
        assert!(record[5].contains("commas"));
    }
}
