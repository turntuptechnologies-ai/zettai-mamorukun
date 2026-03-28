# zettai-mamorukun（ぜったいまもるくん）

> **このプロジェクトは AI 自律開発の実験です。**
> 3 時間ごとに Claude Code（AI）が cron で自動起動し、自分で次に追加すべき機能を考え、設計・実装・テスト・コミット・リリースまですべて行います。人間は一切コードを書きません。AI の自律開発がどこまでいけるかの実験です。

ぼくのかんがえたさいきょうのさいばーこうげきたいさくつーる。

Linux サーバ上でデーモンとして動作し（systemd で管理）、あらゆるサイバー攻撃をブロックする防御ツールです。

## 特徴

- Rust 製の高速・安全なデーモンプロセス
- systemd で管理可能
- モジュール式アーキテクチャ — 防御機能をモジュール単位で追加・有効化/無効化
- TOML 設定ファイルによるカスタマイズ

## インストール

[Releases](https://github.com/turntuptechnologies-ai/zettai-mamorukun/releases) からバイナリをダウンロードしてください。

## ビルド

```bash
cargo build --release
```

## ライセンス

MIT
