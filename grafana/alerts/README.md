# Prometheus アラートルール

zettai-mamorukun の Prometheus エクスポーター（`/metrics`）が公開するメトリクスを
Alertmanager 連携で通知するためのアラートルールサンプルを提供する。

Grafana ダッシュボード（`../zettai-mamorukun-overview.json`）と組み合わせ、
平時の可視化と異常時の通知を一貫して行うことを想定している。

## 前提

- Prometheus 2.40 以降
- Alertmanager が構成済み（Slack / PagerDuty / Webhook 等の通知経路が有効）
- zettai-mamorukun の Prometheus エクスポーターが有効化済み

## 収録ルール

`prometheus_alerts.yaml` に以下の 3 グループ・合計 9 ルールを収録。

### グループ: `zettai-mamorukun.events`

| アラート名 | 重要度 | 条件 | 目的 |
|------------|--------|------|------|
| `ZettaiCriticalEventSurge` | critical | Critical イベントレート > 0.05/s が 5 分継続 | 攻撃兆候・重大インシデントの即時通知 |
| `ZettaiWarningEventSurge` | warning | Warning イベントレート > 0.5/s が 10 分継続 | 軽微な異常の継続発生を検知 |
| `ZettaiModuleEventSpike` | warning | モジュール別レート > 1/s が 5 分継続 | 特定モジュールでの異常集中を検知 |

### グループ: `zettai-mamorukun.scans`

| アラート名 | 重要度 | 条件 | 目的 |
|------------|--------|------|------|
| `ZettaiInitialScanIssuesFound` | warning | 起動時スキャンの問題数 > 0 | 起動直後に検知された問題を通知 |
| `ZettaiInitialScanIssuesCritical` | critical | 起動時スキャンの問題数 >= 5 | 深刻な改ざんの疑いを即時通知 |
| `ZettaiScanDurationP95High` | warning | P95 > 5s が 15 分継続 | パフォーマンス劣化を検知 |
| `ZettaiScanDurationP99Critical` | critical | P99 > 30s が 15 分継続 | 深刻な遅延・ハング兆候を検知 |
| `ZettaiScanStalled` | critical | スキャン実行が 10 分間停止、かつ過去に実行実績あり | モジュールのハング・停止を検知 |

### グループ: `zettai-mamorukun.availability`

| アラート名 | 重要度 | 条件 | 目的 |
|------------|--------|------|------|
| `ZettaiExporterDown` | critical | `up == 0` が 2 分継続 | デーモン停止・ネットワーク障害の検知 |
| `ZettaiNoEventsReceived` | warning | イベントレート 0 が 30 分継続 | モジュール全停止の兆候を検知 |

## 導入方法

### Prometheus 単体構成

`prometheus.yml` の `rule_files` セクションに追加:

```yaml
rule_files:
  - "/etc/prometheus/rules/zettai-mamorukun/prometheus_alerts.yaml"
```

ファイルを配置してから設定をリロード:

```bash
cp grafana/alerts/prometheus_alerts.yaml /etc/prometheus/rules/zettai-mamorukun/
curl -X POST http://localhost:9090/-/reload
```

### Prometheus Operator / kube-prometheus-stack

`PrometheusRule` CRD に書き写して適用:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: zettai-mamorukun
  labels:
    prometheus: kube-prometheus
    role: alert-rules
spec:
  # 以下は prometheus_alerts.yaml の groups: をそのままコピー
  groups:
    - name: zettai-mamorukun.events
      # ...
```

## 検証

ルールの構文検証には `promtool` を使用:

```bash
promtool check rules grafana/alerts/prometheus_alerts.yaml
```

単体テスト用のユニットテストを書く場合は `promtool test rules` を活用可能。

## カスタマイズのヒント

- **閾値**: 環境ごとに発生するイベント数に応じて、`expr` 内の数値を調整する
  （例: 開発環境は感度を上げ、本番は誤検知を減らすため閾値を上げる）
- **for 期間**: 短時間のスパイクを無視したい場合は `for` を長くする
- **重要度ラベル**: `severity` ラベルを Alertmanager のルーティングキーとして使用することを推奨
- **label: `service: zettai-mamorukun`**: Alertmanager の inhibition / grouping に活用する
- **通知メッセージ**: `annotations.summary` / `description` 内の `{{ $labels.module }}` 等は
  Alertmanager 側のテンプレートでも再利用できる

## 関連

- Grafana ダッシュボード: [`../zettai-mamorukun-overview.json`](../zettai-mamorukun-overview.json)
- Grafana README: [`../README.md`](../README.md)
- Prometheus エクスポーター設定: `config.example.toml` の `[prometheus]` セクション
