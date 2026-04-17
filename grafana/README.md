# Grafana ダッシュボード

zettai-mamorukun の Prometheus エクスポーター（`/metrics`）が公開するメトリクスを可視化するためのダッシュボード JSON を提供する。

## 前提

- Grafana 10.0 以降（`schemaVersion: 39`）
- Prometheus データソースが追加済み
- zettai-mamorukun で Prometheus エクスポーターが有効化済み（`config.example.toml` の `[prometheus]` セクション参照）

## インポート方法

Grafana の Web UI から:

1. Dashboards → New → Import
2. `zettai-mamorukun-overview.json` の内容を貼り付け、もしくはファイルをアップロード
3. `DS_PROMETHEUS` に利用中の Prometheus データソースを選択
4. Import を押下

または `grafana-cli` / API 経由:

```bash
curl -X POST \
  -H "Authorization: Bearer $GRAFANA_API_KEY" \
  -H "Content-Type: application/json" \
  -d @<(jq '{dashboard: ., overwrite: true, inputs: [{name: "DS_PROMETHEUS", type: "datasource", pluginId: "prometheus", value: "prometheus"}]}' grafana/zettai-mamorukun-overview.json) \
  https://grafana.example.com/api/dashboards/import
```

## ダッシュボード構成

### 概観

- **総イベント数** — `sum(zettai_events_total)`
- **Info / Warning / Critical イベント** — `zettai_events_by_severity_total{severity=...}` の現在値

### イベント

- **Severity 別イベント流入レート** — `rate(zettai_events_by_severity_total[5m])` を Severity でスタック表示
- **モジュール別イベント件数（Top 10）** — `topk(10, sum by (module) (zettai_module_events_total))`

### スキャン所要時間

- **P50/P95/P99** — `zettai_module_scan_duration_seconds{quantile=...}` をモジュール別に時系列表示
- **平均スキャン所要時間** — `rate(..._sum[5m]) / rate(..._count[5m])`
- **スキャン実行レート** — `rate(zettai_module_scan_duration_seconds_count[5m])`

### 起動時スキャン

- **所要時間** — `zettai_module_initial_scan_duration_seconds`
- **アイテム数** — `zettai_module_initial_scan_items_scanned`
- **検知問題数** — `zettai_module_initial_scan_issues_found`（0 / 1+ / 5+ で色分け）

## テンプレート変数

| 変数名 | 説明 | クエリ |
|--------|------|--------|
| `DS_PROMETHEUS` | Prometheus データソース | — |
| `instance` | 対象ホスト（複数選択可） | `label_values(zettai_events_total, instance)` |
| `module` | 対象モジュール（複数選択可） | `label_values(zettai_module_scan_duration_seconds{instance=~"$instance"}, module)` |

## 参照メトリクス一覧

| メトリクス | 種類 | ラベル | 説明 |
|-----------|------|--------|------|
| `zettai_events_total` | counter | — | 全 SecurityEvent の総数 |
| `zettai_events_by_severity_total` | counter | `severity` | Severity 別イベント数 |
| `zettai_events_by_module_total` | counter | `module` | モジュール別イベント数 |
| `zettai_module_events_total` | counter | `module` | モジュール単位の検知総数 |
| `zettai_module_events_by_severity_total` | counter | `module`, `severity` | モジュール × Severity 別検知数 |
| `zettai_module_initial_scan_duration_seconds` | gauge | `module` | 起動時スキャン実行時間（秒） |
| `zettai_module_initial_scan_items_scanned` | gauge | `module` | 起動時スキャンのアイテム数 |
| `zettai_module_initial_scan_issues_found` | gauge | `module` | 起動時スキャンで検知した問題数 |
| `zettai_module_scan_duration_seconds` | summary | `module`, `quantile` | 定期スキャン実行時間 P50/P95/P99（最新 1024 サンプル） |
| `zettai_module_scan_duration_seconds_count` | counter | `module` | スキャン実行回数（summary のカウンタ部） |
| `zettai_module_scan_duration_seconds_sum` | counter | `module` | スキャン実行時間の累積（summary のサム部） |

## カスタマイズのヒント

- **モジュールのフィルタ**: テンプレート変数 `module` で複数モジュールを絞り込むと、対象パネル（P50/P95/P99、平均、実行レート）が連動する
- **アラート連携**: `zettai_events_by_severity_total{severity="critical"}` の増分で Alertmanager にアラートを飛ばすことを推奨
- **複数インスタンス**: `instance` 変数でインスタンス別の集計・比較が可能

## トラブルシューティング

- **パネルが空**: Prometheus データソースで `up{job="..."}` を確認し、スクレイプが成功しているか確認
- **起動時スキャン系のパネルが空**: そのモジュールが `initial_scan` を実装していない、もしくは起動直後の値が揮発している可能性あり
- **P50/P95/P99 が表示されない**: 対象モジュールの `set_module_stats` 連携が未実装の可能性（CLAUDE.md の「Module Stats Collector」節参照）
