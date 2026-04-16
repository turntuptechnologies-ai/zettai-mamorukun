# zettai-mamorukun（ぜったいまもるくん）

ぼくのかんがえたさいきょうのさいばーこうげきたいさくつーる。
Linux サーバ上でデーモンとして動作し（systemd で管理）、あらゆるサイバー攻撃をブロックする防御ツール。

## プロジェクトフェーズ

現在: **PROTOTYPE**

| フェーズ | 意味 | 状態 |
|---|---|---|
| **PROTOTYPE** | 試作期 | 試作・検証中。コア機能の開発とプロトタイピング |
| **ALPHA / BETA** | 検証期 | 主要機能が揃い、フィードバック収集・改善中 |
| **PREVIEW** | 公開準備期 | 本番環境に近い状態で最終調整 |
| **STABLE** | 安定稼働期 | 正式リリース。安定稼働中 |

## 言語・ツール

- 言語: Rust (edition 2024)
- ビルド: `cargo build --release`
- テスト: `cargo test`
- リント: `cargo clippy -- -D warnings`
- フォーマット: `cargo fmt --check`

## 技術要件

### 動作形態

- Linux デーモンプロセス（systemd unit で管理）
- PID ファイル・ログ出力は systemd / journald に委譲
- 設定ファイルでモジュールの有効/無効を制御

### 設定ファイル

- TOML 形式（`/etc/zettai-mamorukun/config.toml`）
- サンプル: `config.example.toml`

### ログ

- `tracing` + `tracing-subscriber` で構造化ログ
- journald 連携（`tracing-journald` を将来的に検討）

### リリース

- タグ作成時に GitHub Releases へバイナリ（`x86_64-unknown-linux-gnu`）を公開する
- `gh release create` でバイナリをアップロードする
- タグ命名: `v<semver>`（例: `v0.1.0`）

## アーキテクチャ概要

### データフロー

1. **起動** — 設定ファイルを読み込み、有効なモジュールとイベントバスを初期化
2. **監視** — 各モジュールがネットワーク・ログ・プロセス等を監視
3. **検知** — 不審なアクティビティを検知し、イベントバス（`tokio::sync::broadcast`）を通じて `SecurityEvent` を発行
4. **対応** — ブロック・通知等のアクションを実行
5. **記録** — ログサブスクライバーが全イベントを Severity に応じた tracing レベルで構造化ログに記録
6. **リロード** — SIGHUP 受信時に設定ファイルを再読み込みし、モジュールの差分適用（起動・停止・再起動）を行う

### 主要コンポーネント

- **Core**: デーモンのライフサイクル管理、設定読み込み、モジュールの初期化・管理
- **Module System**: 各防御機能をモジュールとして実装するプラグイン的な仕組み
- **Event Bus**: `SecurityEvent` を `tokio::sync::broadcast` で各モジュールからサブスクライバーへ伝達。ログサブスクライバーが全イベントを構造化ログに記録
- **Action Engine**: 検知イベントに対するアクション（ログ・コマンド実行・Webhook 送信）を設定ベースで実行。イベントバスのサブスクライバーとして動作し、Severity やモジュール名に基づくルールマッチングでアクションを選択する
- **Metrics Collector**: SecurityEvent の発生件数・種別・Severity を集計し、定期的にサマリーをログ出力する。イベントバスのサブスクライバーとして動作。`tokio::sync::watch` チャネルによるインターバルのホットリロードに対応
- **Module Stats Collector**: モジュール単位で検知イベント数（Severity 別）と起動時スキャン結果（実行時間・スキャンアイテム数・検知問題数・サマリー）を集計する。MetricsCollector が全体統計を扱うのに対し、こちらはモジュール粒度でパフォーマンスボトルネックや不調モジュールの可視化を支援する。スキャン実行時間はリングバッファ（最新 1024 サンプル）に蓄積され、P50/P95/P99 百分位点・最小/最大/平均を nearest-rank 法で算出する。起動時スキャンに加え、`Module::set_module_stats` で注入された `ModuleStatsHandle` を保持するモジュール（file_integrity / process_monitor / package_verify）は定期スキャンの実行時間もサンプルとして蓄積する。REST API（`/api/v1/stats/modules`、`/api/v1/stats/modules/{name}`）で取得可能。定期サマリーログ出力にも対応。CLI サブコマンド（`zettai-mamorukun module-stats [--module NAME] [--json]`）で REST API 経由での取得にも対応
- **Prometheus Exporter**: MetricsCollector の集計データを Prometheus テキスト形式で HTTP エンドポイント（`/metrics`）から公開する。Grafana・Alertmanager 等の外部監視基盤と連携可能。`/health` エンドポイントでヘルスチェックも提供。TLS（HTTPS）対応により暗号化通信をサポート。mTLS（相互TLS認証）によるクライアント証明書認証に対応（required/optional モード選択可能）。ModuleStatsHandle と連携してモジュール単位の検知数・Severity 別検知数・起動時スキャン実行時間（秒）・スキャンアイテム数・検知問題数に加え、スキャン実行時間の Summary 形式メトリクス（`zettai_module_scan_duration_seconds{module,quantile}` の P50/P95/P99 および `_count` / `_sum`）も公開
- **REST API Server**: HTTP REST API でデーモンのステータス確認、イベント検索、モジュール一覧・制御、設定リロード、アーカイブ操作をリモートから操作可能にする。JSON レスポンス形式で `/api/v1/` プレフィックスのエンドポイントを提供。モジュール制御エンドポイント（`/api/v1/modules/{name}/start|stop|restart`）で個別モジュールの起動・停止・再起動が可能（admin ロール必須、dry_run 対応）。アーカイブエンドポイント（`/api/v1/archives`）でアーカイブ一覧取得・手動アーカイブ実行・復元・ローテーション・個別削除が可能（dry_run 対応、パストラバーサル防止）。イベント集約・サマリーエンドポイント（`/api/v1/events/summary/*`）で時間帯別・モジュール別・Severity別の集計データを提供。モジュール統計エンドポイント（`/api/v1/stats/modules`、`/api/v1/stats/modules/{name}`）でモジュール単位の検知数・起動時スキャン結果を取得可能。WebSocket によるリアルタイムイベントストリーミング（`/api/v1/events/stream`）に対応し、モジュール名・Severity でのフィルタリングが可能。OpenAPI 3.0.3 スキーマ（`/api/v1/openapi.json`）による API ドキュメント提供。TLS（HTTPS）対応により暗号化通信をサポート（rustls ベース、TLS 1.2 以上）。mTLS（相互TLS認証）によるクライアント証明書認証に対応（required/optional モード選択可能）。ホットリロード対応
- **Syslog Forwarder**: SecurityEvent を RFC 5424 形式で外部 Syslog サーバ（SIEM 等）に転送する。UDP/TCP/TLS（RFC 5425）プロトコル対応。TLS 接続時はカスタム CA 証明書またはシステムルート証明書を使用。mTLS（相互TLS認証）によるクライアント証明書認証に対応。イベントバスのサブスクライバーとして動作し、設定ホットリロードに対応
- **Event Store**: SecurityEvent を SQLite データベースに永続保存する。イベントバスのサブスクライバーとして動作し、バッチ挿入・自動クリーンアップ・設定ホットリロードに対応
- **Encryption**: 設定ファイル内の機密値（Webhook URL、認証トークン等）を AES-256-GCM で暗号化・復号する。`ENC[...]` 形式で暗号化された値を設定読み込み時に自動復号。環境変数または鍵ファイルによる鍵管理。CLI コマンド（`encrypt-value`, `decrypt-value`, `generate-key`, `rotate-key`）を提供
- **Module Manager**: モジュールの一括起動・停止・リロードを管理。設定変更の差分検出により、変更のあったモジュールのみ再起動する

## ディレクトリ構成

```
src/
  main.rs              # エントリポイント（デーモン起動）
  lib.rs               # クレートルート
  config.rs            # 設定ファイル読み込み
  encryption.rs        # 設定値の暗号化・復号（AES-256-GCM）
  error.rs             # エラー型定義（thiserror）
  core/
    mod.rs             # コアモジュール
    daemon.rs          # デーモンライフサイクル管理
    action.rs          # アクションエンジン（ルールベースのアクション実行）
    api.rs             # REST API サーバー（HTTP エンドポイント・WebSocket イベントストリーミング）
    correlation.rs     # イベント相関分析エンジン（多段階攻撃パターン検知）
    event.rs           # イベントバス（SecurityEvent / EventBus / ログサブスクライバー）
    event_store.rs     # イベントストア（SQLite 永続化）
    health.rs          # ヘルスチェック（ハートビート・メモリ監視）
    metrics.rs         # イベント統計・メトリクス収集
    module_manager.rs  # モジュールマネージャー（モジュール一括管理・設定ホットリロード）
    module_stats.rs    # モジュール実行統計（モジュール単位の検知数・起動時スキャン結果集計）
    openapi.rs         # OpenAPI 3.0.3 スキーマ生成
    prometheus.rs      # Prometheus メトリクスエクスポーター（HTTP エンドポイント）
    scan_diff.rs       # スキャン状態差分レポート（CLI scan-diff コマンド）
    status.rs          # ステータスサーバー（Unix ソケット経由の CLI ステータス問い合わせ）
    syslog.rs          # Syslog 転送（RFC 5424 形式の SIEM 連携）
  modules/
    mod.rs             # モジュールトレイト・レジストリ
    abstract_socket_monitor.rs # 抽象ソケット名前空間監視モジュール
    at_job_monitor.rs  # at/batch ジョブ監視モジュール
    auditd_monitor.rs  # auditd ログ統合モジュール
    backdoor_detector.rs # ソケットベースのバックドア検知モジュール
    bootloader_monitor.rs # ブートローダー整合性監視モジュール
    capabilities_monitor.rs # Linux capabilities 監視モジュール
    cert_chain_monitor.rs # TLS 証明書チェーン検証モジュール
    cgroup_monitor.rs  # cgroup v2 リソース制限監視モジュール
    container_namespace.rs # コンテナ・名前空間検知モジュール
    coredump_monitor.rs  # コアダンプ設定監視モジュール
    cron_monitor.rs    # Cron ジョブ改ざん検知モジュール（inotify リアルタイム検知対応）
    dbus_monitor.rs    # D-Bus シグナル監視モジュール
    dns_monitor.rs     # DNS設定改ざん検知モジュール
    dns_query_monitor.rs # ネットワーク名前解決監視モジュール
    dynamic_library_monitor.rs # 動的ライブラリインジェクション検知モジュール
    ebpf_monitor.rs    # eBPF プログラム監視モジュール
    env_injection_monitor.rs # 環境変数インジェクション検知モジュール
    fd_monitor.rs      # ファイルディスクリプタ監視モジュール
    fileless_exec_monitor.rs # メモリ内実行（fileless malware）検知モジュール
    file_integrity.rs  # ファイル整合性監視モジュール
    firewall_monitor.rs # ファイアウォールルール監視モジュール
    group_monitor.rs   # グループポリシー監視モジュール
    hidden_process_monitor.rs # プロセス隠蔽検知モジュール
    initramfs_monitor.rs # initramfs 整合性監視モジュール
    inotify_monitor.rs # inotify ベースのリアルタイムファイル変更検知モジュール
    ipc_monitor.rs     # System V IPC 監視モジュール
    journal_pattern_monitor.rs # systemd ジャーナルパターン監視モジュール
    kallsyms_monitor.rs # カーネルシンボルテーブル監視モジュール
    keylogger_detector.rs # キーロガー検知モジュール
    kernel_cmdline_monitor.rs # カーネルコマンドライン実行時監視モジュール
    kernel_module.rs   # カーネルモジュール監視モジュール
    kernel_params.rs   # /proc/sys/ カーネルパラメータ監視モジュール
    kernel_taint_monitor.rs # カーネル taint フラグ監視モジュール
    ld_preload_monitor.rs # 環境変数・LD_PRELOAD 監視モジュール
    listening_port_monitor.rs # リスニングポート監視モジュール
    livepatch_monitor.rs # カーネルライブパッチ監視モジュール
    login_session_monitor.rs # ログインセッション監視モジュール
    log_tamper.rs      # ログファイル改ざん検知モジュール
    mac_monitor.rs     # SELinux/AppArmor 監視モジュール
    mount_monitor.rs   # マウントポイント監視モジュール
    namespace_monitor.rs # namespaces 詳細監視モジュール
    network_interface_monitor.rs # ネットワークインターフェース監視モジュール
    network_monitor.rs # ネットワーク接続監視モジュール
    network_traffic_monitor.rs # ネットワークトラフィック異常検知モジュール
    pam_monitor.rs     # PAM 設定監視モジュール
    privilege_escalation_monitor.rs # プロセス権限昇格検知モジュール
    proc_environ_monitor.rs # プロセス環境変数スナップショット監視モジュール
    process_cmdline_monitor.rs # プロセス起動コマンドライン監視モジュール
    proc_maps_monitor.rs # プロセスメモリマップ監視モジュール
    proc_net_monitor.rs # /proc/net/ 監視モジュール（ルーティング・ARP）
    ptrace_monitor.rs  # ptrace 検知モジュール
    package_verify.rs  # パッケージ整合性検証モジュール
    pkg_repo_monitor.rs # パッケージリポジトリ改ざん検知モジュール
    security_files_monitor.rs # /etc/security/ 監視モジュール
    process_cgroup_monitor.rs # プロセス cgroup 逸脱検知モジュール
    process_exec_monitor.rs # プロセス起動監視モジュール
    process_monitor.rs # プロセス異常検知モジュール
    process_tree_monitor.rs # プロセスツリー監視モジュール
    seccomp_monitor.rs # seccomp プロファイル監視モジュール
    usb_monitor.rs       # USB デバイス監視モジュール
    shell_config_monitor.rs # シェル設定ファイル監視モジュール
    shm_monitor.rs     # 共有メモリ（/dev/shm）監視モジュール
    ssh_brute_force.rs # SSH ブルートフォース検知モジュール
    ssh_key_monitor.rs # SSH公開鍵ファイル監視モジュール
    sshd_config_monitor.rs # SSH 設定セキュリティ監査モジュール
    sudoers_monitor.rs # sudoers ファイル監視モジュール
    suid_sgid_monitor.rs # SUID/SGID ファイル監視モジュール
    swap_tmpfs_monitor.rs # スワップ / tmpfs 監視モジュール
    systemd_service.rs # systemd サービス監視モジュール
    systemd_timer_monitor.rs # systemd タイマーユニット監視モジュール
    tls_cert_monitor.rs # TLS 証明書有効期限監視モジュール
    tmp_exec_monitor.rs # 一時ディレクトリ実行ファイル検知モジュール
    unix_socket_monitor.rs # UNIX ソケット監視モジュール
    user_account.rs    # ユーザーアカウント監視モジュール
    xattr_monitor.rs   # ファイルシステム xattr（拡張属性）監視モジュール
tests/
  integration_test.rs  # 統合テスト
config.example.toml    # 設定ファイルサンプル
zettai-mamorukun.service  # systemd unit ファイル
```

## コーディング規約

- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) に従う
- `cargo fmt` (rustfmt) でフォーマット統一
- `cargo clippy` の警告をすべて解消する
- 命名規則:
  - 型・トレイト: `PascalCase`
  - 関数・変数・モジュール: `snake_case`
  - 定数: `SCREAMING_SNAKE_CASE`
  - ライフタイム: 短い小文字 (`'a`, `'b`)

### unwrap() / expect() ルール

- `unwrap()` / `expect()` はテストコードのみで使用し、本番コードでは `Result` / `Option` を適切に処理する
  - **検査対象**: `src/` 配下の本番コード（`#[cfg(test)]` ブロック、`tests/`、`benches/` は対象外）
  - **対象外（安全）**: `unwrap_or()`, `unwrap_or_default()`, `unwrap_or_else()` は適切なフォールバックがあるため対象外
  - **要修正（パニックリスク）**: 外部入力のパース、ネットワークパケット、ファイル I/O、設定値の処理
  - **許容（コメント必須）**: `Mutex::lock()`、正規表現リテラルの `Regex::new()`、初期化時の致命的エラー
  - 許容する箇所には `// unwrap safety:` コメントで理由を明記する
- `pub` の範囲は最小限にする
- エラー型は `thiserror` で定義し、意味のあるエラーメッセージを付ける
- ドキュメントコメント (`///`) は公開 API に必ず付ける
- `unsafe` の使用は極力避け、使用する場合は `// SAFETY:` コメントで理由を明記する

## テスト戦略

### テストの種類と実行方法

| 種類 | 対象 | 実行コマンド |
|------|------|-------------|
| 単体テスト | 各モジュールのロジック | `cargo test` |
| 統合テスト | デーモン起動・モジュール連携 | `cargo test --test integration_test` |

### テストファイルの配置

- 単体テスト: 同一ファイル内の `#[cfg(test)] mod tests` ブロック
- 統合テスト: `tests/` ディレクトリ

## コミットメッセージ規約

[Conventional Commits](https://www.conventionalcommits.org/) に従う。

```
<type>: <description> (#<issue-number>)
```

### type 一覧

| type | 用途 |
|------|------|
| `feat` | 新機能の追加 |
| `fix` | バグ修正 |
| `docs` | ドキュメントのみの変更 |
| `test` | テストの追加・修正 |
| `refactor` | リファクタリング（機能変更なし） |
| `chore` | ビルド・CI・依存関係等の雑務 |
| `perf` | パフォーマンス改善 |

### ルール

- description は日本語で記述する
- Issue 番号がある場合は末尾に `(#番号)` を付ける
- squash merge 時の PR タイトルもこの規約に従う

## 開発フロー

1. **Issue 作成** — コード・ドキュメント等の変更には必ず Issue を作成する
   - Issue のコメントに調査内容・試行錯誤・判断の経緯を記録する
   - 他の Issue を参照するときは番号だけでなく説明を付けた箇条書きにする（例: `- #3 — ブルートフォース検知モジュール`）
   - 適宜ラベルを付与する
   - `backlog` ラベル: 優先度が低く、通常の開発サイクルでは取り組まない Issue に付与する。「オープンの Issue に取り組んで」等の指示では `backlog` ラベルの Issue は対象外とする
2. **設計** — 設計チームが要件整理・アーキテクチャ設計を行い、Issue に設計内容を記載する
3. **設計レビュー** — レビューチームが設計の妥当性をチェックし、設計チームと相談・調整する
4. **ブランチ作成** — git worktree を使い、Issue に紐づくブランチで作業する
   - ブランチ命名規則: `issue-<番号>/<簡単な説明>` (例: `issue-3/brute-force-detection`)
5. **実装** — 実装チームが設計に基づきコーディングする
   - 不明点は設計チーム・レビューチームに相談する
6. **PR 作成** — Issue を参照する (`Closes #3` 等)
7. **コミット・プッシュ** — 作業中は適宜 commit・push を行う（main ブランチへの直接 push は禁止）
8. **コードレビュー** — マージ前にレビューチームが PR をレビューする
   - セキュリティ観点のチェックを含める（認証・認可の抜け漏れ、入力バリデーション、インジェクション対策等）
9. **マージ** — squash merge を使用する
10. **ブランチ削除** — マージ後にブランチを自動削除する
11. **リリース** — マージ後、タグを作成し GitHub Releases にバイナリを公開する

## チーム体制

| チーム | メンバー | 役割 |
|--------|----------|------|
| 設計 | designer | 要件整理・アーキテクチャ設計・Issue 作成 |
| レビュー | reviewer | 設計の妥当性チェック・PR のコードレビュー |
| 実装 | developer | コーディング・commit・PR 作成 |
| テスト | tester | テストコード作成・品質検証 |
| ドキュメント | documenter | ドキュメント作成・整備 |

## 作業方式

開発作業は必ず Agent Teams（`TeamCreate`）を使い、tmux 画面分割でエージェントが並行作業する形式で進めること。

### 基本ルール

- **Issue ごとにチームを作成する** — 関連する Issue をまとめて 1 チームで対応してもよい
- **チーム構成は以下の順で進行する**:
  1. 設計（designer） — 要件整理・アーキテクチャ設計
  2. レビュー（reviewer） — 設計の妥当性チェック
  3. 実装（developer） — コーディング・commit・PR 作成
  4. テスト（tester） — テストコード作成・品質検証
  5. ドキュメント（documenter） — ドキュメント作成・整備
- **タスクの依存関係を設定する** — 設計完了後にレビュー、レビュー完了後に実装、のように順序を守る
- **設計判断・調査内容は Issue コメントに記録する**
- **tmux 画面分割で並行作業の様子を確認できるようにする**

### チームを使わずに作業してはならない場面

- コード変更を伴う Issue の対応
- 新機能の追加・既存機能の変更
- バグ修正

> **例外**: typo 修正や 1 行の設定変更など、明らかに軽微な変更はチームなしで対応してよい。

## チーム解散前の必須チェック

チームを解散する前に、必ず以下の 3 つの検証を実施すること:

1. **設計との乖離チェック** — ドキュメント（CLAUDE.md, README.md 等）と実装コードに乖離がないか
2. **テストの不足チェック** — 新規・変更コードに対してテストが十分か、カバレッジに穴がないか
3. **ドキュメントの不足チェック** — 新機能・変更がドキュメントに反映されているか

発見された問題は Issue 化して対応してから解散する。

## 自律開発ルール

このプロジェクトは 3 時間ごとの cron で自律的に機能開発を行う。

### 開発サイクル

1. **BACKLOG.md を読む** — 前回の実装後にリストアップされた次回候補を確認する
2. **機能を決定する** — 候補リストから 1 つ選ぶ。ただし **20% の確率でリストを完全に無視**して、自分が実装したいと思う新しいアイデアを採用する
   - 判定方法: 現在時刻の秒数が **5 で割り切れるとき**（0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55）を自由アイデア枠とする（12/60 = 20%、1分間に均等分散）
3. **Issue を作成する** — 実装内容を Issue に書く
4. **Agent Teams で実装する** — CLAUDE.md の開発フローに従う
5. **PR 作成 → レビュー → マージ** — 通常の開発フローに従う
6. **リリースする** — タグを作成し、GitHub Releases にバイナリ（`x86_64-unknown-linux-gnu`）を公開する
7. **BACKLOG.md を更新する** — 次に実装すべき機能の候補をリストアップする（5〜10 項目）

### 倫理ガイドライン

- 非合法な実装は禁止（例: 他者のシステムへの攻撃、マルウェアの作成）
- 他者に危害を加える可能性のある機能は実装しない
- 防御・検知・監視に徹し、攻撃的な機能は実装しない
- プライバシーに配慮し、不必要な個人情報の収集・保存を行わない

## Dependabot PR 対応方針

GitHub Dependabot が依存更新の PR を自動作成する。以下の基準で緊急度を判断し対応する。

| 緊急度 | 条件 | 対応 |
|--------|------|------|
| **即対応** | セキュリティ脆弱性修正（CVE あり、severity: high/critical） | 最優先でビルド・テスト確認後マージ |
| **早めに対応** | セキュリティ修正（severity: moderate/low）、メジャーバージョンアップ | 破壊的変更の有無を確認し、必要なら手動修正して対応 |
| **通常対応** | マイナー/パッチバージョン更新、dev 依存のみの更新 | 通常の開発サイクルで対応 |

## ライセンスルール

- GPL 系ライセンスの依存クレートは使用禁止（商用転用の可能性があるため）
- 許可: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib 等の permissive ライセンス
- 依存追加時はライセンスを必ず確認する

## スコープ制限

- このリポジトリ（turntuptechnologies-ai/zettai-mamorukun）の情報のみ参照すること
- turntuptechnologies-ai Organization 内の他のリポジトリやプライベート情報には一切アクセスしないこと

## 環境ルール

- sudo は使用しない
- ツールやランタイムのインストールには mise を使用する

## 言語ルール

- Issue、コメント、PR の説明、コミットメッセージなど自然言語を書く箇所はすべて日本語で記述する
