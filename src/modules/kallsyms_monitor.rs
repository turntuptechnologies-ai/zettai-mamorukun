//! カーネルシンボルテーブル監視モジュール
//!
//! `/proc/kallsyms` を定期的に読み取り、カーネルシンボルテーブルの変化を監視する。
//!
//! 検知対象:
//! - 新たに追加されたシンボル（ルートキット等による挿入の可能性）
//! - 削除されたシンボル（改ざんの可能性）
//! - シンボルアドレスの変更（カーネルメモリ改ざんの可能性）
//! - 大量の変更が同時に発生した場合の一括検知

use crate::config::KallsymsMonitorConfig;
use crate::core::event::{EventBus, SecurityEvent, Severity};
use crate::error::AppError;
use crate::modules::{InitialScanResult, Module};
use std::collections::{BTreeMap, HashMap};
use tokio_util::sync::CancellationToken;

/// `/proc/kallsyms` の各行をパースした結果
#[derive(Debug, Clone, PartialEq, Eq)]
struct KallsymsEntry {
    /// シンボル名
    name: String,
    /// シンボルアドレス
    address: u64,
    /// シンボルタイプ（T, t, D, d 等）
    symbol_type: char,
    /// モジュール名（カーネルモジュール由来の場合）
    module_name: Option<String>,
}

/// シンボルテーブルの変更内容
#[derive(Debug, Clone, PartialEq, Eq)]
struct KallsymsChanges {
    /// 新しく追加されたシンボル名
    added: Vec<String>,
    /// 削除されたシンボル名
    removed: Vec<String>,
    /// アドレスが変更されたシンボル（名前, 旧アドレス, 新アドレス）
    address_changed: Vec<(String, u64, u64)>,
}

/// カーネルシンボルテーブル監視モジュール
///
/// `/proc/kallsyms` を定期スキャンし、シンボルテーブルの変化を検知してログに記録する。
pub struct KallsymsMonitorModule {
    config: KallsymsMonitorConfig,
    event_bus: Option<EventBus>,
    cancel_token: CancellationToken,
}

impl KallsymsMonitorModule {
    /// 新しいカーネルシンボルテーブル監視モジュールを作成する
    pub fn new(config: KallsymsMonitorConfig, event_bus: Option<EventBus>) -> Self {
        Self {
            config,
            event_bus,
            cancel_token: CancellationToken::new(),
        }
    }

    /// キャンセルトークンのクローンを返す
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// `/proc/kallsyms` の内容を読み取る
    fn read_kallsyms() -> Result<String, AppError> {
        std::fs::read_to_string("/proc/kallsyms").map_err(|e| AppError::FileIo {
            path: "/proc/kallsyms".into(),
            source: e,
        })
    }

    /// `/proc/kallsyms` の内容をパースしてシンボルエントリのリストを返す
    ///
    /// `/proc/kallsyms` の各行は以下の形式:
    /// `address type name [module_name]`
    ///
    /// 例:
    /// - `ffffffff81000000 T _text`
    /// - `ffffffff81000000 t cpu_debug_show [kvm]`
    /// - `0000000000000000 T _text`（非特権ユーザーの場合アドレスがゼロ）
    fn parse_kallsyms(content: &str) -> Vec<KallsymsEntry> {
        let mut entries = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 {
                tracing::debug!(line = line, "不正な /proc/kallsyms 行をスキップしました");
                continue;
            }

            let address = match u64::from_str_radix(fields[0], 16) {
                Ok(a) => a,
                Err(_) => {
                    tracing::debug!(line = line, "アドレスのパースに失敗しました");
                    continue;
                }
            };

            let type_str = fields[1];
            if type_str.len() != 1 {
                tracing::debug!(line = line, "シンボルタイプが不正です");
                continue;
            }
            let symbol_type = type_str.chars().next().unwrap_or(' ');

            let name = fields[2].to_string();

            // オプションのモジュール名: [module_name] 形式
            let module_name = if fields.len() >= 4 {
                let raw = fields[3];
                if raw.starts_with('[') && raw.ends_with(']') {
                    Some(raw[1..raw.len() - 1].to_string())
                } else {
                    None
                }
            } else {
                None
            };

            entries.push(KallsymsEntry {
                name,
                address,
                symbol_type,
                module_name,
            });
        }

        entries
    }

    /// エントリのリストをシンボル名をキーとする HashMap に変換する
    fn entries_to_map(entries: &[KallsymsEntry]) -> HashMap<String, KallsymsEntry> {
        entries
            .iter()
            .map(|e| (e.name.clone(), e.clone()))
            .collect()
    }

    /// ベースラインと現在のシンボルテーブルを比較し、変更を検知する
    ///
    /// アドレス変更の検知は、両方のアドレスが非ゼロの場合にのみ行う
    /// （非特権ユーザーの場合、アドレスがゼロになるため）
    fn detect_changes(
        baseline: &HashMap<String, KallsymsEntry>,
        current: &HashMap<String, KallsymsEntry>,
    ) -> KallsymsChanges {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut address_changed = Vec::new();

        // 新しく追加されたシンボルとアドレス変更を検知
        for (name, current_entry) in current {
            match baseline.get(name) {
                None => {
                    added.push(name.clone());
                }
                Some(baseline_entry) => {
                    // アドレス変更: 両方が非ゼロの場合のみ検知
                    if baseline_entry.address != 0
                        && current_entry.address != 0
                        && baseline_entry.address != current_entry.address
                    {
                        address_changed.push((
                            name.clone(),
                            baseline_entry.address,
                            current_entry.address,
                        ));
                    }
                }
            }
        }

        // 削除されたシンボルを検知
        for name in baseline.keys() {
            if !current.contains_key(name) {
                removed.push(name.clone());
            }
        }

        // 安定したテスト結果のためにソート
        added.sort();
        removed.sort();
        address_changed.sort();

        KallsymsChanges {
            added,
            removed,
            address_changed,
        }
    }
}

impl Module for KallsymsMonitorModule {
    fn name(&self) -> &str {
        "kallsyms_monitor"
    }

    fn init(&mut self) -> Result<(), AppError> {
        if self.config.scan_interval_secs == 0 {
            return Err(AppError::ModuleConfig {
                message: "scan_interval_secs は 0 より大きい値を指定してください".to_string(),
            });
        }

        tracing::info!(
            scan_interval_secs = self.config.scan_interval_secs,
            "カーネルシンボルテーブル監視モジュールを初期化しました"
        );

        Ok(())
    }

    async fn start(&mut self) -> Result<tokio::task::JoinHandle<()>, AppError> {
        // 初回スキャンでベースラインを取得
        let content = Self::read_kallsyms()?;
        let entries = Self::parse_kallsyms(&content);
        let baseline = Self::entries_to_map(&entries);

        tracing::info!(
            symbol_count = baseline.len(),
            "カーネルシンボルテーブルのベースラインを取得しました"
        );

        let scan_interval_secs = self.config.scan_interval_secs;
        let cancel_token = self.cancel_token.clone();
        let event_bus = self.event_bus.clone();

        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(scan_interval_secs));
            // 最初の tick は即座に発火するのでスキップ
            interval.tick().await;

            let mut current_baseline = baseline;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("カーネルシンボルテーブル監視モジュールを停止します");
                        break;
                    }
                    _ = interval.tick() => {
                        let content = match KallsymsMonitorModule::read_kallsyms() {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::warn!(error = %e, "/proc/kallsyms の読み取りに失敗しました");
                                continue;
                            }
                        };

                        let entries = KallsymsMonitorModule::parse_kallsyms(&content);
                        let current = KallsymsMonitorModule::entries_to_map(&entries);

                        let changes = KallsymsMonitorModule::detect_changes(&current_baseline, &current);

                        let total_changes = changes.added.len() + changes.removed.len() + changes.address_changed.len();

                        if total_changes > 100 {
                            // 大量変更の場合は一括イベント
                            tracing::warn!(
                                added = changes.added.len(),
                                removed = changes.removed.len(),
                                address_changed = changes.address_changed.len(),
                                "カーネルシンボルテーブルに大量の変更が検知されました"
                            );
                            if let Some(ref bus) = event_bus {
                                bus.publish(
                                    SecurityEvent::new(
                                        "kallsyms_mass_change",
                                        Severity::Critical,
                                        "kallsyms_monitor",
                                        format!(
                                            "カーネルシンボルテーブルに大量の変更が検知されました: 追加={}, 削除={}, アドレス変更={}",
                                            changes.added.len(),
                                            changes.removed.len(),
                                            changes.address_changed.len(),
                                        ),
                                    )
                                    .with_details(format!("total_changes={}", total_changes)),
                                );
                            }
                        } else {
                            // 個別イベント
                            for symbol_name in &changes.added {
                                tracing::warn!(
                                    symbol_name = %symbol_name,
                                    "新しいカーネルシンボルが追加されました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "kallsyms_symbol_added",
                                            Severity::Warning,
                                            "kallsyms_monitor",
                                            format!("新しいカーネルシンボルが追加されました: {}", symbol_name),
                                        )
                                        .with_details(symbol_name.clone()),
                                    );
                                }
                            }

                            for symbol_name in &changes.removed {
                                tracing::error!(
                                    symbol_name = %symbol_name,
                                    "カーネルシンボルが削除されました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "kallsyms_symbol_removed",
                                            Severity::Critical,
                                            "kallsyms_monitor",
                                            format!("カーネルシンボルが削除されました: {}", symbol_name),
                                        )
                                        .with_details(symbol_name.clone()),
                                    );
                                }
                            }

                            for (symbol_name, old_addr, new_addr) in &changes.address_changed {
                                tracing::warn!(
                                    symbol_name = %symbol_name,
                                    old_address = format!("{:#x}", old_addr),
                                    new_address = format!("{:#x}", new_addr),
                                    "カーネルシンボルのアドレスが変更されました"
                                );
                                if let Some(ref bus) = event_bus {
                                    bus.publish(
                                        SecurityEvent::new(
                                            "kallsyms_address_changed",
                                            Severity::Critical,
                                            "kallsyms_monitor",
                                            format!(
                                                "カーネルシンボルのアドレスが変更されました: {} ({:#x} -> {:#x})",
                                                symbol_name, old_addr, new_addr
                                            ),
                                        )
                                        .with_details(symbol_name.clone()),
                                    );
                                }
                            }
                        }

                        if total_changes == 0 {
                            tracing::debug!("カーネルシンボルテーブルに変化はありません");
                        }

                        // ベースラインを更新
                        current_baseline = current;
                    }
                }
            }
        });

        Ok(handle)
    }

    async fn initial_scan(&self) -> Result<InitialScanResult, AppError> {
        let start = std::time::Instant::now();
        let content = Self::read_kallsyms()?;
        let entries = Self::parse_kallsyms(&content);
        let items_scanned = entries.len();
        let snapshot: BTreeMap<String, String> = entries
            .iter()
            .map(|entry| {
                (
                    entry.name.clone(),
                    format!("addr={:x},type={}", entry.address, entry.symbol_type),
                )
            })
            .collect();
        let duration = start.elapsed();

        Ok(InitialScanResult {
            items_scanned,
            issues_found: 0,
            duration,
            summary: format!("カーネルシンボル {}件を検出しました", items_scanned),
            snapshot,
        })
    }

    async fn stop(&mut self) -> Result<(), AppError> {
        self.cancel_token.cancel();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kallsyms_normal() {
        let content = "\
ffffffff81000000 T _text
ffffffff81000100 t cpu_debug_show [kvm]
ffffffff81000200 D some_data";

        let entries = KallsymsMonitorModule::parse_kallsyms(content);
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].name, "_text");
        assert_eq!(entries[0].address, 0xffffffff81000000);
        assert_eq!(entries[0].symbol_type, 'T');
        assert_eq!(entries[0].module_name, None);

        assert_eq!(entries[1].name, "cpu_debug_show");
        assert_eq!(entries[1].address, 0xffffffff81000100);
        assert_eq!(entries[1].symbol_type, 't');
        assert_eq!(entries[1].module_name, Some("kvm".to_string()));

        assert_eq!(entries[2].name, "some_data");
        assert_eq!(entries[2].address, 0xffffffff81000200);
        assert_eq!(entries[2].symbol_type, 'D');
        assert_eq!(entries[2].module_name, None);
    }

    #[test]
    fn test_parse_kallsyms_empty() {
        let entries = KallsymsMonitorModule::parse_kallsyms("");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_kallsyms_zeroed_addresses() {
        let content = "\
0000000000000000 T _text
0000000000000000 t some_func
0000000000000000 D some_data";

        let entries = KallsymsMonitorModule::parse_kallsyms(content);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].address, 0);
        assert_eq!(entries[1].address, 0);
        assert_eq!(entries[2].address, 0);
    }

    #[test]
    fn test_parse_kallsyms_invalid_lines() {
        let content = "\
ffffffff81000000 T _text
invalid_line
abc
ffffffff81000100 XX bad_type
ffffffff81000200 D valid_symbol";

        let entries = KallsymsMonitorModule::parse_kallsyms(content);
        // "invalid_line" -> 1 field, skipped
        // "abc" -> 1 field, skipped
        // "ffffffff81000100 XX bad_type" -> XX is 2 chars, skipped
        // valid: _text and valid_symbol
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "_text");
        assert_eq!(entries[1].name, "valid_symbol");
    }

    #[test]
    fn test_detect_changes_no_change() {
        let entry = KallsymsEntry {
            name: "sym_a".to_string(),
            address: 0xffffffff81000000,
            symbol_type: 'T',
            module_name: None,
        };
        let mut baseline = HashMap::new();
        baseline.insert("sym_a".to_string(), entry.clone());
        let current = baseline.clone();

        let changes = KallsymsMonitorModule::detect_changes(&baseline, &current);
        assert!(changes.added.is_empty());
        assert!(changes.removed.is_empty());
        assert!(changes.address_changed.is_empty());
    }

    #[test]
    fn test_detect_changes_added() {
        let baseline: HashMap<String, KallsymsEntry> = HashMap::new();
        let mut current = HashMap::new();
        current.insert(
            "new_sym".to_string(),
            KallsymsEntry {
                name: "new_sym".to_string(),
                address: 0xffffffff81000000,
                symbol_type: 'T',
                module_name: None,
            },
        );

        let changes = KallsymsMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(changes.added, vec!["new_sym".to_string()]);
        assert!(changes.removed.is_empty());
        assert!(changes.address_changed.is_empty());
    }

    #[test]
    fn test_detect_changes_removed() {
        let mut baseline = HashMap::new();
        baseline.insert(
            "old_sym".to_string(),
            KallsymsEntry {
                name: "old_sym".to_string(),
                address: 0xffffffff81000000,
                symbol_type: 'T',
                module_name: None,
            },
        );
        let current: HashMap<String, KallsymsEntry> = HashMap::new();

        let changes = KallsymsMonitorModule::detect_changes(&baseline, &current);
        assert!(changes.added.is_empty());
        assert_eq!(changes.removed, vec!["old_sym".to_string()]);
        assert!(changes.address_changed.is_empty());
    }

    #[test]
    fn test_detect_changes_address_changed() {
        let mut baseline = HashMap::new();
        baseline.insert(
            "sym_a".to_string(),
            KallsymsEntry {
                name: "sym_a".to_string(),
                address: 0xffffffff81000000,
                symbol_type: 'T',
                module_name: None,
            },
        );
        let mut current = HashMap::new();
        current.insert(
            "sym_a".to_string(),
            KallsymsEntry {
                name: "sym_a".to_string(),
                address: 0xffffffff82000000,
                symbol_type: 'T',
                module_name: None,
            },
        );

        let changes = KallsymsMonitorModule::detect_changes(&baseline, &current);
        assert!(changes.added.is_empty());
        assert!(changes.removed.is_empty());
        assert_eq!(
            changes.address_changed,
            vec![("sym_a".to_string(), 0xffffffff81000000, 0xffffffff82000000)]
        );
    }

    #[test]
    fn test_detect_changes_mixed() {
        let mut baseline = HashMap::new();
        baseline.insert(
            "sym_a".to_string(),
            KallsymsEntry {
                name: "sym_a".to_string(),
                address: 0xffffffff81000000,
                symbol_type: 'T',
                module_name: None,
            },
        );
        baseline.insert(
            "sym_b".to_string(),
            KallsymsEntry {
                name: "sym_b".to_string(),
                address: 0xffffffff81000100,
                symbol_type: 'T',
                module_name: None,
            },
        );
        baseline.insert(
            "sym_c".to_string(),
            KallsymsEntry {
                name: "sym_c".to_string(),
                address: 0xffffffff81000200,
                symbol_type: 'D',
                module_name: None,
            },
        );

        let mut current = HashMap::new();
        // sym_a: アドレス変更
        current.insert(
            "sym_a".to_string(),
            KallsymsEntry {
                name: "sym_a".to_string(),
                address: 0xffffffff82000000,
                symbol_type: 'T',
                module_name: None,
            },
        );
        // sym_b: 削除（current に含めない）
        // sym_c: 変化なし
        current.insert(
            "sym_c".to_string(),
            KallsymsEntry {
                name: "sym_c".to_string(),
                address: 0xffffffff81000200,
                symbol_type: 'D',
                module_name: None,
            },
        );
        // sym_d: 追加
        current.insert(
            "sym_d".to_string(),
            KallsymsEntry {
                name: "sym_d".to_string(),
                address: 0xffffffff81000300,
                symbol_type: 't',
                module_name: Some("kvm".to_string()),
            },
        );

        let changes = KallsymsMonitorModule::detect_changes(&baseline, &current);
        assert_eq!(changes.added, vec!["sym_d".to_string()]);
        assert_eq!(changes.removed, vec!["sym_b".to_string()]);
        assert_eq!(
            changes.address_changed,
            vec![("sym_a".to_string(), 0xffffffff81000000, 0xffffffff82000000)]
        );
    }

    #[test]
    fn test_detect_changes_skip_zero_address() {
        let mut baseline = HashMap::new();
        baseline.insert(
            "sym_a".to_string(),
            KallsymsEntry {
                name: "sym_a".to_string(),
                address: 0,
                symbol_type: 'T',
                module_name: None,
            },
        );
        let mut current = HashMap::new();
        current.insert(
            "sym_a".to_string(),
            KallsymsEntry {
                name: "sym_a".to_string(),
                address: 0,
                symbol_type: 'T',
                module_name: None,
            },
        );

        let changes = KallsymsMonitorModule::detect_changes(&baseline, &current);
        assert!(changes.address_changed.is_empty());

        // ベースラインがゼロ、現在が非ゼロの場合もスキップ
        let mut baseline2 = HashMap::new();
        baseline2.insert(
            "sym_b".to_string(),
            KallsymsEntry {
                name: "sym_b".to_string(),
                address: 0,
                symbol_type: 'T',
                module_name: None,
            },
        );
        let mut current2 = HashMap::new();
        current2.insert(
            "sym_b".to_string(),
            KallsymsEntry {
                name: "sym_b".to_string(),
                address: 0xffffffff81000000,
                symbol_type: 'T',
                module_name: None,
            },
        );

        let changes2 = KallsymsMonitorModule::detect_changes(&baseline2, &current2);
        assert!(changes2.address_changed.is_empty());
    }

    #[test]
    fn test_init_zero_interval() {
        let config = KallsymsMonitorConfig {
            enabled: true,
            scan_interval_secs: 0,
        };
        let mut module = KallsymsMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_init_valid_config() {
        let config = KallsymsMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
        };
        let mut module = KallsymsMonitorModule::new(config, None);
        let result = module.init();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let config = KallsymsMonitorConfig {
            enabled: true,
            scan_interval_secs: 3600,
        };
        let mut module = KallsymsMonitorModule::new(config, None);
        module.init().unwrap();

        let cancel_token = module.cancel_token();
        module.start().await.unwrap();

        module.stop().await.unwrap();
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_initial_scan() {
        let config = KallsymsMonitorConfig {
            enabled: true,
            scan_interval_secs: 300,
        };
        let module = KallsymsMonitorModule::new(config, None);

        let result = module.initial_scan().await.unwrap();
        // Linux 環境では /proc/kallsyms には必ずシンボルが存在する
        assert!(result.items_scanned > 0);
        assert_eq!(result.issues_found, 0);
        assert!(result.summary.contains("件を検出しました"));
    }

    #[test]
    fn test_kallsyms_entry_fields() {
        let entry = KallsymsEntry {
            name: "test_symbol".to_string(),
            address: 0xdeadbeef,
            symbol_type: 'T',
            module_name: Some("test_mod".to_string()),
        };
        assert_eq!(entry.name, "test_symbol");
        assert_eq!(entry.address, 0xdeadbeef);
        assert_eq!(entry.symbol_type, 'T');
        assert_eq!(entry.module_name, Some("test_mod".to_string()));

        let entry_no_mod = KallsymsEntry {
            name: "bare_symbol".to_string(),
            address: 0xcafebabe,
            symbol_type: 'd',
            module_name: None,
        };
        assert_eq!(entry_no_mod.module_name, None);
    }
}
