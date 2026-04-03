//! スキャン状態の永続化 — 起動時スキャン結果の保存・読み込み・差分検出

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::SystemTime;
use tracing::{info, warn};

/// 永続化されるスキャン状態
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanState {
    /// 保存日時（RFC 3339 形式）
    pub saved_at: String,
    /// 各モジュールのスナップショット（モジュール名 → アイテム識別子 → ハッシュ/状態文字列）
    pub modules: BTreeMap<String, BTreeMap<String, String>>,
}

/// スナップショットの差分種別
#[derive(Debug, PartialEq, Eq)]
pub enum DiffKind {
    /// 新規追加されたアイテム
    Added,
    /// 削除されたアイテム
    Removed,
    /// 変更されたアイテム
    Modified,
}

/// 個別の差分エントリ
#[derive(Debug)]
pub struct DiffEntry {
    /// 差分種別
    pub kind: DiffKind,
    /// アイテム識別子（ファイルパス等）
    pub key: String,
    /// 前回の値（Added の場合は None）
    pub old_value: Option<String>,
    /// 今回の値（Removed の場合は None）
    pub new_value: Option<String>,
}

/// モジュール単位の差分結果
#[derive(Debug)]
pub struct ModuleDiff {
    /// モジュール名
    pub module_name: String,
    /// 差分エントリのリスト
    pub entries: Vec<DiffEntry>,
}

impl ModuleDiff {
    /// 差分があるかどうかを返す
    pub fn has_changes(&self) -> bool {
        !self.entries.is_empty()
    }
}

/// 前回のスキャン状態をファイルから読み込む
///
/// ファイルが存在しない場合は `None` を返す。
/// パースに失敗した場合はログ警告を出して `None` を返す。
pub fn load_scan_state(path: &Path) -> Option<ScanState> {
    if !path.exists() {
        info!(path = %path.display(), "前回のスキャン状態ファイルが存在しません（初回起動）");
        return None;
    }

    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<ScanState>(&content) {
            Ok(state) => {
                info!(
                    path = %path.display(),
                    saved_at = %state.saved_at,
                    modules = state.modules.len(),
                    "前回のスキャン状態を読み込みました"
                );
                Some(state)
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "スキャン状態ファイルのパースに失敗しました。差分検出をスキップします"
                );
                None
            }
        },
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "スキャン状態ファイルの読み込みに失敗しました。差分検出をスキップします"
            );
            None
        }
    }
}

/// スキャン状態をファイルに保存する
///
/// アトミック書き込み（一時ファイル→リネーム）を使用する。
/// 書き込みに失敗してもデーモン動作には影響しない（ログ警告のみ）。
pub fn save_scan_state(path: &Path, modules: &[(String, BTreeMap<String, String>)]) {
    let saved_at = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => format!("{}", d.as_secs()),
        Err(_) => "0".to_string(),
    };
    let state = ScanState {
        saved_at,
        modules: modules.iter().cloned().collect(),
    };

    let json = match serde_json::to_string_pretty(&state) {
        Ok(j) => j,
        Err(e) => {
            warn!(error = %e, "スキャン状態の JSON シリアライズに失敗しました");
            return;
        }
    };

    // 親ディレクトリを作成
    if let Some(parent) = path.parent()
        && !parent.exists()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        warn!(
            path = %parent.display(),
            error = %e,
            "スキャン状態保存先ディレクトリの作成に失敗しました"
        );
        return;
    }

    // 一時ファイルに書き込み→リネーム（アトミック書き込み）
    let tmp_path = path.with_extension("json.tmp");
    match std::fs::write(&tmp_path, &json) {
        Ok(()) => match std::fs::rename(&tmp_path, path) {
            Ok(()) => {
                info!(
                    path = %path.display(),
                    modules = state.modules.len(),
                    "スキャン状態を保存しました"
                );
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "スキャン状態ファイルのリネームに失敗しました"
                );
                // 一時ファイルのクリーンアップ
                let _ = std::fs::remove_file(&tmp_path);
            }
        },
        Err(e) => {
            warn!(
                path = %tmp_path.display(),
                error = %e,
                "スキャン状態の一時ファイル書き込みに失敗しました"
            );
        }
    }
}

/// 前回と今回のスナップショットを比較し、差分を検出する
pub fn detect_diffs(
    previous: &ScanState,
    current_modules: &[(String, BTreeMap<String, String>)],
) -> Vec<ModuleDiff> {
    let mut diffs = Vec::new();

    for (module_name, current_snapshot) in current_modules {
        let mut entries = Vec::new();

        if let Some(prev_snapshot) = previous.modules.get(module_name) {
            // 変更・削除の検出
            for (key, old_value) in prev_snapshot {
                match current_snapshot.get(key) {
                    Some(new_value) if new_value != old_value => {
                        entries.push(DiffEntry {
                            kind: DiffKind::Modified,
                            key: key.clone(),
                            old_value: Some(old_value.clone()),
                            new_value: Some(new_value.clone()),
                        });
                    }
                    None => {
                        entries.push(DiffEntry {
                            kind: DiffKind::Removed,
                            key: key.clone(),
                            old_value: Some(old_value.clone()),
                            new_value: None,
                        });
                    }
                    _ => {} // 変更なし
                }
            }

            // 追加の検出
            for (key, new_value) in current_snapshot {
                if !prev_snapshot.contains_key(key) {
                    entries.push(DiffEntry {
                        kind: DiffKind::Added,
                        key: key.clone(),
                        old_value: None,
                        new_value: Some(new_value.clone()),
                    });
                }
            }
        }
        // 前回のスナップショットにモジュールが存在しない場合は差分なし（初回とみなす）

        if !entries.is_empty() {
            diffs.push(ModuleDiff {
                module_name: module_name.clone(),
                entries,
            });
        }
    }

    diffs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_scan_state_nonexistent() {
        let result = load_scan_state(Path::new("/tmp/nonexistent-scan-state-zettai-test.json"));
        assert!(result.is_none());
    }

    #[test]
    fn test_load_scan_state_invalid_json() {
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "not valid json").unwrap();
        let result = load_scan_state(tmpfile.path());
        assert!(result.is_none());
    }

    #[test]
    fn test_load_scan_state_valid() {
        let mut tmpfile = NamedTempFile::new().unwrap();
        let state = ScanState {
            saved_at: "2026-04-03T00:00:00Z".to_string(),
            modules: BTreeMap::from([(
                "module_a".to_string(),
                BTreeMap::from([("/etc/file".to_string(), "abc123".to_string())]),
            )]),
        };
        let json = serde_json::to_string(&state).unwrap();
        write!(tmpfile, "{}", json).unwrap();
        let result = load_scan_state(tmpfile.path());
        assert!(result.is_some());
        let loaded = result.unwrap();
        assert_eq!(loaded.modules.len(), 1);
        assert!(loaded.modules.contains_key("module_a"));
    }

    #[test]
    fn test_save_scan_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan_state.json");
        let modules = vec![(
            "module_a".to_string(),
            BTreeMap::from([("/etc/file".to_string(), "abc123".to_string())]),
        )];
        save_scan_state(&path, &modules);
        assert!(path.exists());

        let loaded = load_scan_state(&path);
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.modules.len(), 1);
    }

    #[test]
    fn test_save_scan_state_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir").join("scan_state.json");
        let modules = vec![];
        save_scan_state(&path, &modules);
        assert!(path.exists());
    }

    #[test]
    fn test_detect_diffs_no_changes() {
        let previous = ScanState {
            saved_at: "2026-04-03T00:00:00Z".to_string(),
            modules: BTreeMap::from([(
                "mod_a".to_string(),
                BTreeMap::from([("/a".to_string(), "hash1".to_string())]),
            )]),
        };
        let current = vec![(
            "mod_a".to_string(),
            BTreeMap::from([("/a".to_string(), "hash1".to_string())]),
        )];
        let diffs = detect_diffs(&previous, &current);
        assert!(diffs.is_empty());
    }

    #[test]
    fn test_detect_diffs_added() {
        let previous = ScanState {
            saved_at: "2026-04-03T00:00:00Z".to_string(),
            modules: BTreeMap::from([(
                "mod_a".to_string(),
                BTreeMap::from([("/a".to_string(), "hash1".to_string())]),
            )]),
        };
        let current = vec![(
            "mod_a".to_string(),
            BTreeMap::from([
                ("/a".to_string(), "hash1".to_string()),
                ("/b".to_string(), "hash2".to_string()),
            ]),
        )];
        let diffs = detect_diffs(&previous, &current);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].entries.len(), 1);
        assert_eq!(diffs[0].entries[0].kind, DiffKind::Added);
        assert_eq!(diffs[0].entries[0].key, "/b");
    }

    #[test]
    fn test_detect_diffs_removed() {
        let previous = ScanState {
            saved_at: "2026-04-03T00:00:00Z".to_string(),
            modules: BTreeMap::from([(
                "mod_a".to_string(),
                BTreeMap::from([
                    ("/a".to_string(), "hash1".to_string()),
                    ("/b".to_string(), "hash2".to_string()),
                ]),
            )]),
        };
        let current = vec![(
            "mod_a".to_string(),
            BTreeMap::from([("/a".to_string(), "hash1".to_string())]),
        )];
        let diffs = detect_diffs(&previous, &current);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].entries.len(), 1);
        assert_eq!(diffs[0].entries[0].kind, DiffKind::Removed);
        assert_eq!(diffs[0].entries[0].key, "/b");
    }

    #[test]
    fn test_detect_diffs_modified() {
        let previous = ScanState {
            saved_at: "2026-04-03T00:00:00Z".to_string(),
            modules: BTreeMap::from([(
                "mod_a".to_string(),
                BTreeMap::from([("/a".to_string(), "hash1".to_string())]),
            )]),
        };
        let current = vec![(
            "mod_a".to_string(),
            BTreeMap::from([("/a".to_string(), "hash_changed".to_string())]),
        )];
        let diffs = detect_diffs(&previous, &current);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].entries.len(), 1);
        assert_eq!(diffs[0].entries[0].kind, DiffKind::Modified);
        assert_eq!(diffs[0].entries[0].old_value, Some("hash1".to_string()));
        assert_eq!(
            diffs[0].entries[0].new_value,
            Some("hash_changed".to_string())
        );
    }

    #[test]
    fn test_detect_diffs_new_module() {
        let previous = ScanState {
            saved_at: "2026-04-03T00:00:00Z".to_string(),
            modules: BTreeMap::new(),
        };
        let current = vec![(
            "mod_a".to_string(),
            BTreeMap::from([("/a".to_string(), "hash1".to_string())]),
        )];
        // 前回にモジュールが存在しない場合は差分なし（初回とみなす）
        let diffs = detect_diffs(&previous, &current);
        assert!(diffs.is_empty());
    }

    #[test]
    fn test_detect_diffs_combined() {
        let previous = ScanState {
            saved_at: "2026-04-03T00:00:00Z".to_string(),
            modules: BTreeMap::from([(
                "mod_a".to_string(),
                BTreeMap::from([
                    ("/existing".to_string(), "hash1".to_string()),
                    ("/to_remove".to_string(), "hash2".to_string()),
                    ("/to_modify".to_string(), "hash3".to_string()),
                ]),
            )]),
        };
        let current = vec![(
            "mod_a".to_string(),
            BTreeMap::from([
                ("/existing".to_string(), "hash1".to_string()),
                ("/to_modify".to_string(), "hash_changed".to_string()),
                ("/new_file".to_string(), "hash4".to_string()),
            ]),
        )];
        let diffs = detect_diffs(&previous, &current);
        assert_eq!(diffs.len(), 1);
        let diff = &diffs[0];
        assert_eq!(diff.entries.len(), 3); // modified + removed + added

        let added: Vec<_> = diff
            .entries
            .iter()
            .filter(|e| e.kind == DiffKind::Added)
            .collect();
        let removed: Vec<_> = diff
            .entries
            .iter()
            .filter(|e| e.kind == DiffKind::Removed)
            .collect();
        let modified: Vec<_> = diff
            .entries
            .iter()
            .filter(|e| e.kind == DiffKind::Modified)
            .collect();

        assert_eq!(added.len(), 1);
        assert_eq!(removed.len(), 1);
        assert_eq!(modified.len(), 1);
        assert_eq!(added[0].key, "/new_file");
        assert_eq!(removed[0].key, "/to_remove");
        assert_eq!(modified[0].key, "/to_modify");
    }

    #[test]
    fn test_module_diff_has_changes() {
        let diff = ModuleDiff {
            module_name: "test".to_string(),
            entries: vec![DiffEntry {
                kind: DiffKind::Added,
                key: "/new".to_string(),
                old_value: None,
                new_value: Some("hash".to_string()),
            }],
        };
        assert!(diff.has_changes());

        let empty_diff = ModuleDiff {
            module_name: "test".to_string(),
            entries: vec![],
        };
        assert!(!empty_diff.has_changes());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let modules = vec![
            (
                "mod_a".to_string(),
                BTreeMap::from([
                    ("/etc/file1".to_string(), "hash1".to_string()),
                    ("/etc/file2".to_string(), "hash2".to_string()),
                ]),
            ),
            (
                "mod_b".to_string(),
                BTreeMap::from([("kernel_mod".to_string(), "loaded".to_string())]),
            ),
        ];

        save_scan_state(&path, &modules);
        let loaded = load_scan_state(&path).unwrap();
        assert_eq!(loaded.modules.len(), 2);
        assert_eq!(
            loaded.modules["mod_a"].get("/etc/file1"),
            Some(&"hash1".to_string())
        );
        assert_eq!(
            loaded.modules["mod_b"].get("kernel_mod"),
            Some(&"loaded".to_string())
        );
    }

    #[test]
    fn test_detect_diffs_multiple_modules() {
        let previous = ScanState {
            saved_at: "2026-04-03T00:00:00Z".to_string(),
            modules: BTreeMap::from([
                (
                    "mod_a".to_string(),
                    BTreeMap::from([("/a".to_string(), "hash1".to_string())]),
                ),
                (
                    "mod_b".to_string(),
                    BTreeMap::from([("/b".to_string(), "hash2".to_string())]),
                ),
            ]),
        };
        let current = vec![
            (
                "mod_a".to_string(),
                BTreeMap::from([("/a".to_string(), "hash_changed".to_string())]),
            ),
            (
                "mod_b".to_string(),
                BTreeMap::from([("/b".to_string(), "hash2".to_string())]),
            ),
        ];
        let diffs = detect_diffs(&previous, &current);
        // mod_a のみ差分あり
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].module_name, "mod_a");
    }
}
