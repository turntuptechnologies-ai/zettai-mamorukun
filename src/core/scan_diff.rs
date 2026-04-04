//! スキャン状態の差分レポート -- CLI scan-diff コマンドのロジック

use crate::config::AppConfig;
use crate::core::module_manager::ModuleManager;
use crate::core::scan_state::{self, DiffKind, ModuleDiff, ScanState};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::SystemTime;

/// scan-diff の出力オプション
pub struct ScanDiffOptions {
    /// 特定モジュールのみ表示するフィルタ
    pub module_filter: Option<String>,
    /// JSON 形式で出力するかどうか
    pub json_output: bool,
}

/// JSON出力用の差分レポート構造体
#[derive(Serialize)]
struct DiffReport {
    previous_scan_at: String,
    current_scan_at: String,
    modules: Vec<ModuleReport>,
    total_modules_changed: usize,
    total_changes: usize,
}

/// JSON出力用のモジュールレポート
#[derive(Serialize)]
struct ModuleReport {
    name: String,
    changes: Vec<ChangeEntry>,
}

/// JSON出力用の変更エントリ
#[derive(Serialize)]
struct ChangeEntry {
    kind: String,
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_value: Option<String>,
}

/// scan-diff コマンドを実行する
///
/// 戻り値: 差分があったかどうか。エラー時は Err を返す。
pub async fn run_scan_diff(
    config: &AppConfig,
    state_file_override: Option<&Path>,
    options: &ScanDiffOptions,
) -> Result<bool, Box<dyn std::error::Error>> {
    let state_path = state_file_override
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from(&config.startup_scan.state_file));

    // スキャン状態ファイル読み込み
    let previous_state = scan_state::load_scan_state(&state_path);
    let previous_state = match previous_state {
        Some(s) => s,
        None => {
            eprintln!(
                "エラー: スキャン状態ファイルが見つかりません: {}",
                state_path.display()
            );
            eprintln!("デーモンを一度起動してスキャン状態を保存してください。");
            return Err("スキャン状態ファイルが見つかりません".into());
        }
    };

    eprintln!("前回スキャン: {}", previous_state.saved_at);
    eprintln!("現在の状態をスキャンしています...");

    // 現在のスキャン実行
    let scan_report = ModuleManager::run_scan_only(&config.modules).await;

    // スナップショット収集
    let current_modules: Vec<(String, BTreeMap<String, String>)> = scan_report
        .results
        .iter()
        .map(|(name, result)| (name.clone(), result.snapshot.clone()))
        .collect();

    // 差分検出
    let mut diffs = scan_state::detect_diffs(&previous_state, &current_modules);

    // モジュールフィルタ
    if let Some(ref filter) = options.module_filter {
        diffs.retain(|d| d.module_name.contains(filter));
    }

    let has_diff = !diffs.is_empty();

    if options.json_output {
        print_json_report(&previous_state, &diffs);
    } else {
        print_text_report(&previous_state, &diffs);
    }

    Ok(has_diff)
}

/// テキスト形式で差分レポートを出力する
fn print_text_report(previous: &ScanState, diffs: &[ModuleDiff]) {
    println!("=== スキャン状態差分レポート ===");
    println!("前回スキャン: {}", previous.saved_at);
    println!();

    if diffs.is_empty() {
        println!("差分はありません。");
        return;
    }

    let mut total_changes = 0;
    for diff in diffs {
        println!("[{}] {} 件の変更", diff.module_name, diff.entries.len());
        for entry in &diff.entries {
            let symbol = match entry.kind {
                DiffKind::Added => "+",
                DiffKind::Removed => "-",
                DiffKind::Modified => "~",
            };
            let label = match entry.kind {
                DiffKind::Added => "追加",
                DiffKind::Removed => "削除",
                DiffKind::Modified => "変更",
            };
            println!("  {} {} ({})", symbol, entry.key, label);
        }
        total_changes += diff.entries.len();
        println!();
    }

    println!(
        "合計: {} モジュール, {} 件の変更",
        diffs.len(),
        total_changes
    );
}

/// JSON 形式で差分レポートを出力する
fn print_json_report(previous: &ScanState, diffs: &[ModuleDiff]) {
    let current_timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| format!("{}", d.as_secs()))
        .unwrap_or_else(|_| "0".to_string());

    let total_changes: usize = diffs.iter().map(|d| d.entries.len()).sum();
    let modules: Vec<ModuleReport> = diffs
        .iter()
        .map(|diff| {
            let changes: Vec<ChangeEntry> = diff
                .entries
                .iter()
                .map(|entry| ChangeEntry {
                    kind: match entry.kind {
                        DiffKind::Added => "added".to_string(),
                        DiffKind::Removed => "removed".to_string(),
                        DiffKind::Modified => "modified".to_string(),
                    },
                    key: entry.key.clone(),
                    old_value: entry.old_value.clone(),
                    new_value: entry.new_value.clone(),
                })
                .collect();
            ModuleReport {
                name: diff.module_name.clone(),
                changes,
            }
        })
        .collect();

    let report = DiffReport {
        previous_scan_at: previous.saved_at.clone(),
        current_scan_at: current_timestamp,
        total_modules_changed: diffs.len(),
        total_changes,
        modules,
    };

    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("エラー: JSON シリアライズに失敗しました: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan_state::{DiffEntry, DiffKind, ModuleDiff, ScanState};
    use std::collections::BTreeMap;

    fn make_previous_state() -> ScanState {
        ScanState {
            saved_at: "1712188800".to_string(),
            modules: BTreeMap::from([(
                "mod_a".to_string(),
                BTreeMap::from([("/etc/file".to_string(), "abc123".to_string())]),
            )]),
        }
    }

    #[test]
    fn test_print_text_report_no_diff() {
        let previous = make_previous_state();
        let diffs: Vec<ModuleDiff> = vec![];
        // 差分なし時にパニックしないことを確認
        print_text_report(&previous, &diffs);
    }

    #[test]
    fn test_print_text_report_with_diff() {
        let previous = make_previous_state();
        let diffs = vec![ModuleDiff {
            module_name: "mod_a".to_string(),
            entries: vec![
                DiffEntry {
                    kind: DiffKind::Added,
                    key: "/etc/new_file".to_string(),
                    old_value: None,
                    new_value: Some("hash1".to_string()),
                },
                DiffEntry {
                    kind: DiffKind::Removed,
                    key: "/etc/old_file".to_string(),
                    old_value: Some("hash2".to_string()),
                    new_value: None,
                },
                DiffEntry {
                    kind: DiffKind::Modified,
                    key: "/etc/changed_file".to_string(),
                    old_value: Some("hash3".to_string()),
                    new_value: Some("hash4".to_string()),
                },
            ],
        }];
        // 差分あり時にパニックしないことを確認
        print_text_report(&previous, &diffs);
    }

    #[test]
    fn test_print_json_report() {
        let previous = make_previous_state();
        let diffs = vec![ModuleDiff {
            module_name: "mod_a".to_string(),
            entries: vec![DiffEntry {
                kind: DiffKind::Added,
                key: "/etc/new_file".to_string(),
                old_value: None,
                new_value: Some("hash1".to_string()),
            }],
        }];
        // JSON出力がパニックしないことを確認
        print_json_report(&previous, &diffs);
    }
}
