//! OpenAPI 3.0 スキーマ生成
//!
//! REST API のエンドポイント定義から OpenAPI 3.0.3 仕様書を生成する。

use serde_json::{Value, json};

/// OpenAPI 3.0.3 仕様書を JSON として生成する
pub fn generate_openapi_schema() -> Value {
    json!({
        "openapi": "3.0.3",
        "info": {
            "title": "zettai-mamorukun REST API",
            "description": "Linux セキュリティ監視デーモン zettai-mamorukun の REST API",
            "version": env!("CARGO_PKG_VERSION"),
            "license": {
                "name": "MIT"
            }
        },
        "servers": [
            {
                "url": "/api/v1",
                "description": "API v1"
            }
        ],
        "paths": {
            "/api/v1/health": health_path(),
            "/api/v1/status": status_path(),
            "/api/v1/modules": modules_path(),
            "/api/v1/events": events_path(),
            "/api/v1/reload": reload_path(),
            "/api/v1/events/stream": events_stream_path(),
            "/api/v1/openapi.json": openapi_path(),
            "/api/v1/events/batch/delete": batch_delete_path(),
            "/api/v1/events/batch/export": batch_export_path(),
            "/api/v1/events/batch/acknowledge": batch_acknowledge_path(),
            "/api/v1/score": score_path(),
            "/api/v1/archives": archives_list_create_path(),
            "/api/v1/archives/restore": archives_restore_path(),
            "/api/v1/archives/rotate": archives_rotate_path(),
            "/api/v1/archives/{filename}": archives_delete_path(),
            "/api/v1/webhooks": webhooks_list_path(),
            "/api/v1/webhooks/test": webhooks_test_path(),
            "/api/v1/events/summary": events_summary_path(),
            "/api/v1/events/summary/timeline": events_summary_timeline_path(),
            "/api/v1/events/summary/modules": events_summary_modules_path(),
            "/api/v1/events/summary/severity": events_summary_severity_path(),
            "/api/v1/modules/{name}/start": module_start_path(),
            "/api/v1/modules/{name}/stop": module_stop_path(),
            "/api/v1/modules/{name}/restart": module_restart_path(),
            "/api/v1/stats/modules": stats_modules_path(),
            "/api/v1/stats/modules/{name}": stats_module_path(),
        },
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "API トークン認証。`zettai-mamorukun hash-token <TOKEN>` でハッシュを生成し、設定ファイルに登録する"
                }
            },
            "schemas": component_schemas(),
        }
    })
}

fn health_path() -> Value {
    json!({
        "get": {
            "summary": "ヘルスチェック",
            "description": "API サーバーの稼働状態を返す。認証不要。",
            "operationId": "getHealth",
            "tags": ["system"],
            "responses": {
                "200": {
                    "description": "正常稼働中",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "status": {
                                        "type": "string",
                                        "enum": ["ok"],
                                        "example": "ok"
                                    }
                                },
                                "required": ["status"]
                            }
                        }
                    }
                }
            }
        }
    })
}

fn status_path() -> Value {
    json!({
        "get": {
            "summary": "デーモンステータス",
            "description": "デーモンのバージョン、稼働時間、有効モジュール、メトリクスサマリーを返す。",
            "operationId": "getStatus",
            "tags": ["system"],
            "security": [{"BearerAuth": []}],
            "responses": {
                "200": {
                    "description": "ステータス情報",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/StatusResponse"
                            }
                        }
                    }
                },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "403": { "$ref": "#/components/schemas/ErrorResponse" }
            }
        }
    })
}

fn modules_path() -> Value {
    json!({
        "get": {
            "summary": "モジュール一覧",
            "description": "有効な監視モジュールの一覧とリスタート回数を返す。",
            "operationId": "getModules",
            "tags": ["modules"],
            "security": [{"BearerAuth": []}],
            "responses": {
                "200": {
                    "description": "モジュール一覧",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/ModulesResponse"
                            }
                        }
                    }
                },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "403": { "$ref": "#/components/schemas/ErrorResponse" }
            }
        }
    })
}

fn events_path() -> Value {
    json!({
        "get": {
            "summary": "イベント検索",
            "description": "SQLite イベントストアからセキュリティイベントを検索する。",
            "operationId": "getEvents",
            "tags": ["events"],
            "security": [{"BearerAuth": []}],
            "parameters": [
                {
                    "name": "q",
                    "in": "query",
                    "description": "フルテキスト検索クエリ（FTS5 MATCH 構文。AND/OR/NOT/フレーズ検索対応）",
                    "required": false,
                    "schema": { "type": "string" }
                },
                {
                    "name": "severity",
                    "in": "query",
                    "description": "Severity でフィルタリング（info, warning, critical）",
                    "required": false,
                    "schema": {
                        "type": "string",
                        "enum": ["info", "warning", "critical"]
                    }
                },
                {
                    "name": "module",
                    "in": "query",
                    "description": "ソースモジュール名でフィルタリング",
                    "required": false,
                    "schema": { "type": "string" }
                },
                {
                    "name": "since",
                    "in": "query",
                    "description": "開始日時（ISO 8601 形式: YYYY-MM-DDTHH:MM:SSZ または YYYY-MM-DD）",
                    "required": false,
                    "schema": { "type": "string", "format": "date-time" }
                },
                {
                    "name": "until",
                    "in": "query",
                    "description": "終了日時（ISO 8601 形式）",
                    "required": false,
                    "schema": { "type": "string", "format": "date-time" }
                },
                {
                    "name": "limit",
                    "in": "query",
                    "description": "最大取得件数（デフォルト: 50、上限: 200）",
                    "required": false,
                    "schema": {
                        "type": "integer",
                        "default": 50,
                        "minimum": 1,
                        "maximum": 200
                    }
                },
                {
                    "name": "cursor",
                    "in": "query",
                    "description": "ページネーションカーソル（イベント ID）。指定した ID より古いイベントを取得する",
                    "required": false,
                    "schema": {
                        "type": "integer",
                        "format": "int64"
                    }
                }
            ],
            "responses": {
                "200": {
                    "description": "イベント一覧",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/PaginatedEventsResponse"
                            }
                        }
                    }
                },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "403": { "$ref": "#/components/schemas/ErrorResponse" },
                "503": {
                    "description": "イベントストアが無効",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn reload_path() -> Value {
    json!({
        "post": {
            "summary": "設定リロード",
            "description": "設定ファイルを再読み込みし、変更のあったモジュールを再起動する。admin ロールが必要。dry_run=true で設定ファイルのバリデーションのみ実行する。",
            "operationId": "postReload",
            "tags": ["system"],
            "security": [{"BearerAuth": []}],
            "parameters": [
                {
                    "name": "dry_run",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "boolean", "default": false },
                    "description": "true の場合、実際のリロードを行わず設定ファイルのバリデーション結果のみ返す"
                }
            ],
            "responses": {
                "200": {
                    "description": "リロード成功または dry-run 結果",
                    "content": {
                        "application/json": {
                            "schema": {
                                "oneOf": [
                                    {
                                        "type": "object",
                                        "properties": {
                                            "message": {
                                                "type": "string",
                                                "example": "リロードをトリガーしました"
                                            }
                                        },
                                        "required": ["message"]
                                    },
                                    { "$ref": "#/components/schemas/DryRunReloadResponse" }
                                ]
                            }
                        }
                    }
                },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "403": { "$ref": "#/components/schemas/ErrorResponse" },
                "500": {
                    "description": "リロード失敗",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn events_stream_path() -> Value {
    json!({
        "get": {
            "summary": "イベントストリーミング（WebSocket）",
            "description": "WebSocket でセキュリティイベントをリアルタイムにストリーミングする。Upgrade: websocket ヘッダーが必要。認証は Authorization ヘッダーまたは token クエリパラメータで行う。",
            "operationId": "getEventsStream",
            "tags": ["events"],
            "security": [{"BearerAuth": []}],
            "parameters": [
                {
                    "name": "module",
                    "in": "query",
                    "description": "モジュール名フィルタ（カンマ区切りで複数指定可能）",
                    "required": false,
                    "schema": { "type": "string" }
                },
                {
                    "name": "severity",
                    "in": "query",
                    "description": "最小 Severity フィルタ",
                    "required": false,
                    "schema": {
                        "type": "string",
                        "enum": ["info", "warning", "critical"]
                    }
                },
                {
                    "name": "token",
                    "in": "query",
                    "description": "Bearer トークン（Authorization ヘッダーの代替）",
                    "required": false,
                    "schema": { "type": "string" }
                }
            ],
            "responses": {
                "101": {
                    "description": "WebSocket Upgrade 成功。各メッセージは SecurityEvent の JSON。",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/SecurityEvent"
                            }
                        }
                    }
                },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "426": {
                    "description": "WebSocket Upgrade が必要",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                },
                "503": {
                    "description": "WebSocket が無効または接続数上限",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn openapi_path() -> Value {
    json!({
        "get": {
            "summary": "OpenAPI スキーマ",
            "description": "この API の OpenAPI 3.0.3 仕様書を JSON 形式で返す。認証不要。",
            "operationId": "getOpenApiSchema",
            "tags": ["system"],
            "responses": {
                "200": {
                    "description": "OpenAPI 3.0.3 仕様書",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "description": "OpenAPI 3.0.3 仕様書"
                            }
                        }
                    }
                }
            }
        }
    })
}

fn batch_delete_path() -> Value {
    json!({
        "post": {
            "summary": "イベント一括削除",
            "description": "ID 指定またはフィルタ条件でイベントを一括削除する。admin ロールが必要。dry_run=true で影響範囲のみ確認する。",
            "operationId": "postBatchDelete",
            "tags": ["events"],
            "security": [{"BearerAuth": []}],
            "parameters": [
                {
                    "name": "dry_run",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "boolean", "default": false },
                    "description": "true の場合、実際の削除を行わず影響範囲のみ返す"
                }
            ],
            "requestBody": {
                "required": true,
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/BatchDeleteRequest" }
                    }
                }
            },
            "responses": {
                "200": {
                    "description": "削除成功または dry-run 結果",
                    "content": {
                        "application/json": {
                            "schema": {
                                "oneOf": [
                                    { "$ref": "#/components/schemas/BatchDeleteResponse" },
                                    { "$ref": "#/components/schemas/DryRunBatchResponse" }
                                ]
                            }
                        }
                    }
                },
                "400": { "$ref": "#/components/schemas/ErrorResponse" },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "403": { "$ref": "#/components/schemas/ErrorResponse" },
                "503": {
                    "description": "イベントストアが無効",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn batch_export_path() -> Value {
    json!({
        "post": {
            "summary": "イベント一括エクスポート",
            "description": "フィルタ条件でイベントを一括エクスポートする。read_only ロール以上が必要。",
            "operationId": "postBatchExport",
            "tags": ["events"],
            "security": [{"BearerAuth": []}],
            "requestBody": {
                "required": true,
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/BatchExportRequest" }
                    }
                }
            },
            "responses": {
                "200": {
                    "description": "エクスポート成功",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/BatchExportResponse" }
                        }
                    }
                },
                "400": { "$ref": "#/components/schemas/ErrorResponse" },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "403": { "$ref": "#/components/schemas/ErrorResponse" },
                "503": {
                    "description": "イベントストアが無効",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn batch_acknowledge_path() -> Value {
    json!({
        "post": {
            "summary": "イベント一括確認済みマーク",
            "description": "ID 指定でイベントを一括確認済みにする。admin ロールが必要。dry_run=true で影響範囲のみ確認する。",
            "operationId": "postBatchAcknowledge",
            "tags": ["events"],
            "security": [{"BearerAuth": []}],
            "parameters": [
                {
                    "name": "dry_run",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "boolean", "default": false },
                    "description": "true の場合、実際の確認済みマークを行わず影響範囲のみ返す"
                }
            ],
            "requestBody": {
                "required": true,
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/BatchAcknowledgeRequest" }
                    }
                }
            },
            "responses": {
                "200": {
                    "description": "確認済みマーク成功または dry-run 結果",
                    "content": {
                        "application/json": {
                            "schema": {
                                "oneOf": [
                                    { "$ref": "#/components/schemas/BatchAcknowledgeResponse" },
                                    { "$ref": "#/components/schemas/DryRunBatchResponse" }
                                ]
                            }
                        }
                    }
                },
                "400": { "$ref": "#/components/schemas/ErrorResponse" },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "403": { "$ref": "#/components/schemas/ErrorResponse" },
                "503": {
                    "description": "イベントストアが無効",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn score_path() -> Value {
    json!({
        "get": {
            "summary": "セキュリティスコア取得",
            "description": "システム全体のセキュリティスコアとカテゴリ別評価を返す。",
            "operationId": "getScore",
            "tags": ["security"],
            "security": [{"BearerAuth": []}],
            "responses": {
                "200": {
                    "description": "スコア取得成功",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/SecurityScore" }
                        }
                    }
                },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "503": {
                    "description": "スコアリングが無効",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn archives_list_create_path() -> Value {
    json!({
        "get": {
            "summary": "アーカイブ一覧取得",
            "description": "アーカイブファイルの一覧を返す。read_only ロール以上が必要。",
            "operationId": "getArchives",
            "tags": ["archives"],
            "security": [{"BearerAuth": []}],
            "responses": {
                "200": {
                    "description": "アーカイブ一覧",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ArchiveListResponse" }
                        }
                    }
                },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "503": {
                    "description": "アーカイブ機能が無効",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        },
        "post": {
            "summary": "手動アーカイブ実行",
            "description": "イベントストアのイベントを手動でアーカイブする。admin ロールが必要。dry_run=true でプレビュー。",
            "operationId": "postArchives",
            "tags": ["archives"],
            "security": [{"BearerAuth": []}],
            "parameters": [
                {
                    "name": "dry_run",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "boolean", "default": false },
                    "description": "true の場合、実際のアーカイブを行わずプレビューのみ返す"
                }
            ],
            "requestBody": {
                "required": false,
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/ArchiveCreateRequest" }
                    }
                }
            },
            "responses": {
                "200": {
                    "description": "アーカイブ成功または dry-run 結果",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ArchiveCreateResponse" }
                        }
                    }
                },
                "400": { "$ref": "#/components/schemas/ErrorResponse" },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "403": { "$ref": "#/components/schemas/ErrorResponse" },
                "503": {
                    "description": "アーカイブ機能またはイベントストアが無効",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn archives_restore_path() -> Value {
    json!({
        "post": {
            "summary": "アーカイブ復元",
            "description": "アーカイブファイルからイベントをイベントストアに復元する。admin ロールが必要。dry_run=true でプレビュー。",
            "operationId": "postArchivesRestore",
            "tags": ["archives"],
            "security": [{"BearerAuth": []}],
            "parameters": [
                {
                    "name": "dry_run",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "boolean", "default": false },
                    "description": "true の場合、実際の復元を行わずプレビューのみ返す"
                }
            ],
            "requestBody": {
                "required": true,
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/ArchiveRestoreRequest" }
                    }
                }
            },
            "responses": {
                "200": {
                    "description": "復元成功または dry-run 結果",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ArchiveRestoreResponse" }
                        }
                    }
                },
                "400": { "$ref": "#/components/schemas/ErrorResponse" },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "403": { "$ref": "#/components/schemas/ErrorResponse" },
                "503": {
                    "description": "アーカイブ機能またはイベントストアが無効",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn archives_rotate_path() -> Value {
    json!({
        "post": {
            "summary": "アーカイブローテーション",
            "description": "アーカイブファイルのローテーション（古いファイルの削除）を実行する。admin ロールが必要。dry_run=true でプレビュー。",
            "operationId": "postArchivesRotate",
            "tags": ["archives"],
            "security": [{"BearerAuth": []}],
            "parameters": [
                {
                    "name": "dry_run",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "boolean", "default": false },
                    "description": "true の場合、実際のローテーションを行わずプレビューのみ返す"
                }
            ],
            "requestBody": {
                "required": false,
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/ArchiveRotateRequest" }
                    }
                }
            },
            "responses": {
                "200": {
                    "description": "ローテーション成功または dry-run 結果",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ArchiveRotateResponse" }
                        }
                    }
                },
                "400": { "$ref": "#/components/schemas/ErrorResponse" },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "403": { "$ref": "#/components/schemas/ErrorResponse" },
                "503": {
                    "description": "アーカイブ機能が無効",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn archives_delete_path() -> Value {
    json!({
        "delete": {
            "summary": "アーカイブファイル削除",
            "description": "指定されたアーカイブファイルを削除する。admin ロールが必要。dry_run=true でプレビュー。",
            "operationId": "deleteArchive",
            "tags": ["archives"],
            "security": [{"BearerAuth": []}],
            "parameters": [
                {
                    "name": "filename",
                    "in": "path",
                    "required": true,
                    "schema": { "type": "string" },
                    "description": "削除するアーカイブファイル名"
                },
                {
                    "name": "dry_run",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "boolean", "default": false },
                    "description": "true の場合、実際の削除を行わずプレビューのみ返す"
                }
            ],
            "responses": {
                "200": {
                    "description": "削除成功または dry-run 結果",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ArchiveDeleteResponse" }
                        }
                    }
                },
                "400": { "$ref": "#/components/schemas/ErrorResponse" },
                "401": { "$ref": "#/components/schemas/ErrorResponse" },
                "403": { "$ref": "#/components/schemas/ErrorResponse" },
                "404": {
                    "description": "アーカイブファイルが見つからない",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                },
                "503": {
                    "description": "アーカイブ機能が無効",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn webhooks_list_path() -> Value {
    json!({
        "get": {
            "summary": "Webhook 一覧取得",
            "description": "設定済みの Webhook 通知先一覧を取得する。URL はマスク表示。",
            "operationId": "listWebhooks",
            "tags": ["webhooks"],
            "security": [{ "BearerAuth": [] }],
            "responses": {
                "200": {
                    "description": "Webhook 一覧",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "webhooks": {
                                        "type": "array",
                                        "items": {
                                            "$ref": "#/components/schemas/WebhookInfo"
                                        }
                                    },
                                    "total": {
                                        "type": "integer",
                                        "description": "Webhook 総数"
                                    }
                                }
                            }
                        }
                    }
                },
                "401": {
                    "description": "認証エラー"
                }
            }
        }
    })
}

fn webhooks_test_path() -> Value {
    json!({
        "post": {
            "summary": "Webhook テスト送信",
            "description": "指定した Webhook にテスト用イベントを送信し、接続性を確認する。",
            "operationId": "testWebhook",
            "tags": ["webhooks"],
            "security": [{ "BearerAuth": [] }],
            "requestBody": {
                "required": true,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["name"],
                            "properties": {
                                "name": {
                                    "type": "string",
                                    "description": "テスト送信する Webhook 名"
                                }
                            }
                        }
                    }
                }
            },
            "responses": {
                "200": {
                    "description": "テスト送信成功",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/WebhookTestResult"
                            }
                        }
                    }
                },
                "404": {
                    "description": "指定した Webhook が見つからない"
                },
                "502": {
                    "description": "Webhook 送信失敗"
                }
            }
        }
    })
}

fn module_control_params() -> Value {
    json!([{
        "name": "name",
        "in": "path",
        "required": true,
        "schema": { "type": "string" },
        "description": "モジュール名"
    }, {
        "name": "dry_run",
        "in": "query",
        "required": false,
        "schema": { "type": "boolean", "default": false },
        "description": "true の場合、実際の操作を行わずバリデーションのみ実行する"
    }])
}

fn module_control_responses() -> Value {
    json!({
        "200": {
            "description": "操作成功",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ModuleControlResponse" }
                }
            }
        },
        "404": {
            "description": "モジュールが見つからない",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                }
            }
        },
        "409": {
            "description": "状態の競合（既に起動中/停止中）",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                }
            }
        }
    })
}

fn module_start_path() -> Value {
    json!({
        "post": {
            "summary": "モジュール起動",
            "description": "指定したモジュールを起動する。既に起動中の場合は 409 Conflict を返す。",
            "operationId": "startModule",
            "tags": ["modules"],
            "security": [{ "BearerAuth": [] }],
            "parameters": module_control_params(),
            "responses": module_control_responses()
        }
    })
}

fn module_stop_path() -> Value {
    json!({
        "post": {
            "summary": "モジュール停止",
            "description": "指定したモジュールを停止する。既に停止中の場合は 409 Conflict を返す。",
            "operationId": "stopModule",
            "tags": ["modules"],
            "security": [{ "BearerAuth": [] }],
            "parameters": module_control_params(),
            "responses": module_control_responses()
        }
    })
}

fn module_restart_path() -> Value {
    json!({
        "post": {
            "summary": "モジュール再起動",
            "description": "指定したモジュールを再起動する。停止中の場合は起動する。",
            "operationId": "restartModule",
            "tags": ["modules"],
            "security": [{ "BearerAuth": [] }],
            "parameters": module_control_params(),
            "responses": module_control_responses()
        }
    })
}

fn stats_modules_path() -> Value {
    json!({
        "get": {
            "summary": "モジュール実行統計一覧",
            "description": "全モジュールの実行統計（検知イベント数、起動時スキャン結果等）を返す。",
            "operationId": "listModuleStats",
            "tags": ["stats"],
            "security": [{ "BearerAuth": [] }],
            "responses": {
                "200": {
                    "description": "モジュール統計一覧",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "total": { "type": "integer", "example": 70 },
                                    "modules": {
                                        "type": "array",
                                        "items": { "$ref": "#/components/schemas/ModuleStats" }
                                    }
                                },
                                "required": ["total", "modules"]
                            }
                        }
                    }
                },
                "503": {
                    "description": "モジュール実行統計が無効です",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn stats_module_path() -> Value {
    json!({
        "get": {
            "summary": "モジュール実行統計（個別）",
            "description": "指定したモジュールの実行統計を返す。",
            "operationId": "getModuleStats",
            "tags": ["stats"],
            "security": [{ "BearerAuth": [] }],
            "parameters": [
                {
                    "name": "name",
                    "in": "path",
                    "description": "モジュール名",
                    "required": true,
                    "schema": { "type": "string" }
                }
            ],
            "responses": {
                "200": {
                    "description": "モジュール統計",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ModuleStats" }
                        }
                    }
                },
                "404": {
                    "description": "モジュールが見つかりません",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                },
                "503": {
                    "description": "モジュール実行統計が無効です",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                        }
                    }
                }
            }
        }
    })
}

fn summary_common_params() -> Value {
    json!([
        {
            "name": "since",
            "in": "query",
            "description": "開始日時（ISO 8601 形式: YYYY-MM-DDTHH:MM:SSZ または YYYY-MM-DD）。デフォルト: 7日前",
            "required": false,
            "schema": { "type": "string", "format": "date-time" }
        },
        {
            "name": "until",
            "in": "query",
            "description": "終了日時（ISO 8601 形式）。デフォルト: 現在",
            "required": false,
            "schema": { "type": "string", "format": "date-time" }
        },
        {
            "name": "module",
            "in": "query",
            "description": "ソースモジュール名でフィルタリング",
            "required": false,
            "schema": { "type": "string" }
        },
        {
            "name": "severity",
            "in": "query",
            "description": "Severity でフィルタリング（INFO, WARNING, CRITICAL）",
            "required": false,
            "schema": {
                "type": "string",
                "enum": ["INFO", "WARNING", "CRITICAL"]
            }
        }
    ])
}

fn summary_error_responses() -> Value {
    json!({
        "400": {
            "description": "リクエストパラメータが不正",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                }
            }
        },
        "401": { "$ref": "#/components/schemas/ErrorResponse" },
        "503": {
            "description": "イベントストアが無効",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                }
            }
        }
    })
}

fn events_summary_path() -> Value {
    let mut responses = serde_json::Map::new();
    responses.insert("200".to_string(), json!({
        "description": "イベントサマリー（総件数・Severity別・モジュール別）",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "total": { "type": "integer", "description": "総件数" },
                        "since": { "type": "integer", "description": "開始タイムスタンプ（UNIX 秒）" },
                        "until": { "type": "integer", "description": "終了タイムスタンプ（UNIX 秒）" },
                        "by_severity": {
                            "type": "object",
                            "additionalProperties": { "type": "integer" },
                            "description": "Severity 別件数"
                        },
                        "by_module": {
                            "type": "object",
                            "additionalProperties": { "type": "integer" },
                            "description": "モジュール別件数（上位20件）"
                        }
                    },
                    "required": ["total", "since", "until", "by_severity", "by_module"]
                }
            }
        }
    }));
    let err = summary_error_responses();
    if let Value::Object(err_map) = err {
        for (k, v) in err_map {
            responses.insert(k, v);
        }
    }
    json!({
        "get": {
            "summary": "イベントサマリー",
            "description": "指定期間のイベント総件数、Severity 別件数、モジュール別件数を返す。",
            "operationId": "getEventsSummary",
            "tags": ["events"],
            "security": [{"BearerAuth": []}],
            "parameters": summary_common_params(),
            "responses": Value::Object(responses)
        }
    })
}

fn events_summary_timeline_path() -> Value {
    let mut params = summary_common_params()
        .as_array()
        .cloned()
        .unwrap_or_default();
    params.push(json!({
        "name": "interval",
        "in": "query",
        "description": "集計間隔（hour, day, week）。デフォルト: day",
        "required": false,
        "schema": {
            "type": "string",
            "enum": ["hour", "day", "week"],
            "default": "day"
        }
    }));
    let mut responses = serde_json::Map::new();
    responses.insert("200".to_string(), json!({
        "description": "時系列イベント集計",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "interval": { "type": "string", "description": "集計間隔" },
                        "since": { "type": "integer", "description": "開始タイムスタンプ（UNIX 秒）" },
                        "until": { "type": "integer", "description": "終了タイムスタンプ（UNIX 秒）" },
                        "buckets": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "timestamp": { "type": "integer", "description": "バケット開始タイムスタンプ（UNIX 秒）" },
                                    "count": { "type": "integer", "description": "件数" }
                                },
                                "required": ["timestamp", "count"]
                            }
                        }
                    },
                    "required": ["interval", "since", "until", "buckets"]
                }
            }
        }
    }));
    let err = summary_error_responses();
    if let Value::Object(err_map) = err {
        for (k, v) in err_map {
            responses.insert(k, v);
        }
    }
    json!({
        "get": {
            "summary": "イベントタイムライン",
            "description": "指定期間のイベントを時系列で集計する。欠損バケットは 0 で補完される。",
            "operationId": "getEventsSummaryTimeline",
            "tags": ["events"],
            "security": [{"BearerAuth": []}],
            "parameters": params,
            "responses": Value::Object(responses)
        }
    })
}

fn events_summary_modules_path() -> Value {
    let mut params = summary_common_params()
        .as_array()
        .cloned()
        .unwrap_or_default();
    params.push(json!({
        "name": "limit",
        "in": "query",
        "description": "最大取得件数（デフォルト: 20、上限: 200）",
        "required": false,
        "schema": {
            "type": "integer",
            "default": 20,
            "minimum": 1,
            "maximum": 200
        }
    }));
    let mut responses = serde_json::Map::new();
    responses.insert("200".to_string(), json!({
        "description": "モジュール別イベント集計",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "since": { "type": "integer", "description": "開始タイムスタンプ（UNIX 秒）" },
                        "until": { "type": "integer", "description": "終了タイムスタンプ（UNIX 秒）" },
                        "modules": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "module": { "type": "string", "description": "モジュール名" },
                                    "count": { "type": "integer", "description": "件数" },
                                    "latest_timestamp": { "type": "integer", "description": "最新イベントのタイムスタンプ（UNIX 秒）" }
                                },
                                "required": ["module", "count", "latest_timestamp"]
                            }
                        }
                    },
                    "required": ["since", "until", "modules"]
                }
            }
        }
    }));
    let err = summary_error_responses();
    if let Value::Object(err_map) = err {
        for (k, v) in err_map {
            responses.insert(k, v);
        }
    }
    json!({
        "get": {
            "summary": "モジュール別イベントサマリー",
            "description": "指定期間のイベントをモジュール別に集計する。件数降順でソート。",
            "operationId": "getEventsSummaryModules",
            "tags": ["events"],
            "security": [{"BearerAuth": []}],
            "parameters": params,
            "responses": Value::Object(responses)
        }
    })
}

fn events_summary_severity_path() -> Value {
    let mut responses = serde_json::Map::new();
    responses.insert("200".to_string(), json!({
        "description": "Severity 別イベント集計",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "since": { "type": "integer", "description": "開始タイムスタンプ（UNIX 秒）" },
                        "until": { "type": "integer", "description": "終了タイムスタンプ（UNIX 秒）" },
                        "total": { "type": "integer", "description": "総件数" },
                        "severities": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "severity": { "type": "string", "description": "Severity 名" },
                                    "count": { "type": "integer", "description": "件数" },
                                    "percentage": { "type": "number", "format": "double", "description": "割合（%）" }
                                },
                                "required": ["severity", "count", "percentage"]
                            }
                        }
                    },
                    "required": ["since", "until", "total", "severities"]
                }
            }
        }
    }));
    let err = summary_error_responses();
    if let Value::Object(err_map) = err {
        for (k, v) in err_map {
            responses.insert(k, v);
        }
    }
    json!({
        "get": {
            "summary": "Severity 別イベントサマリー",
            "description": "指定期間のイベントを Severity 別に集計する。割合（パーセンテージ）も含む。",
            "operationId": "getEventsSummarySeverity",
            "tags": ["events"],
            "security": [{"BearerAuth": []}],
            "parameters": summary_common_params(),
            "responses": Value::Object(responses)
        }
    })
}

fn component_schemas() -> Value {
    json!({
        "ErrorResponse": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string",
                    "description": "エラーメッセージ"
                }
            },
            "required": ["error"]
        },
        "StatusResponse": {
            "type": "object",
            "properties": {
                "version": {
                    "type": "string",
                    "description": "デーモンバージョン",
                    "example": "1.26.0"
                },
                "uptime_secs": {
                    "type": "integer",
                    "description": "稼働時間（秒）",
                    "example": 3600
                },
                "modules": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "有効モジュール名の一覧"
                },
                "metrics": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/MetricsSummary" },
                        { "type": "null" }
                    ],
                    "description": "メトリクスサマリー（メトリクスが無効の場合は null）"
                },
                "module_restarts": {
                    "type": "object",
                    "additionalProperties": { "type": "integer" },
                    "description": "モジュールごとのリスタート回数"
                }
            },
            "required": ["version", "uptime_secs", "modules", "metrics", "module_restarts"]
        },
        "MetricsSummary": {
            "type": "object",
            "properties": {
                "total_events": {
                    "type": "integer",
                    "description": "イベント総数"
                },
                "info_count": {
                    "type": "integer",
                    "description": "Info イベント数"
                },
                "warning_count": {
                    "type": "integer",
                    "description": "Warning イベント数"
                },
                "critical_count": {
                    "type": "integer",
                    "description": "Critical イベント数"
                },
                "module_counts": {
                    "type": "object",
                    "additionalProperties": { "type": "integer" },
                    "description": "モジュールごとのイベント数"
                }
            },
            "required": ["total_events", "info_count", "warning_count", "critical_count", "module_counts"]
        },
        "ModuleStats": {
            "type": "object",
            "properties": {
                "module": { "type": "string", "description": "モジュール名" },
                "events_total": { "type": "integer", "description": "検知イベント総数" },
                "events_info": { "type": "integer", "description": "INFO レベル検知数" },
                "events_warning": { "type": "integer", "description": "WARNING レベル検知数" },
                "events_critical": { "type": "integer", "description": "CRITICAL レベル検知数" },
                "last_event_at": {
                    "type": "string",
                    "nullable": true,
                    "format": "date-time",
                    "description": "直近の検知イベントタイムスタンプ（RFC3339 UTC）"
                },
                "initial_scan_duration_ms": {
                    "type": "integer",
                    "nullable": true,
                    "description": "起動時スキャンの実行時間（ミリ秒）"
                },
                "initial_scan_items_scanned": {
                    "type": "integer",
                    "nullable": true,
                    "description": "起動時スキャンでスキャンしたアイテム数"
                },
                "initial_scan_issues_found": {
                    "type": "integer",
                    "nullable": true,
                    "description": "起動時スキャンで検知された問題数"
                },
                "initial_scan_summary": {
                    "type": "string",
                    "nullable": true,
                    "description": "起動時スキャンのサマリーメッセージ"
                },
                "initial_scan_at": {
                    "type": "string",
                    "nullable": true,
                    "format": "date-time",
                    "description": "起動時スキャン実行時刻（RFC3339 UTC）"
                },
                "scan_count": {
                    "type": "integer",
                    "description": "スキャン実行回数（ヒストグラムの累積サンプル数）"
                },
                "scan_total_ms": {
                    "type": "integer",
                    "nullable": true,
                    "description": "スキャン実行時間の累積（ミリ秒）"
                },
                "scan_min_ms": {
                    "type": "integer",
                    "nullable": true,
                    "description": "スキャン実行時間の最小値（ミリ秒、直近 1024 サンプル内）"
                },
                "scan_max_ms": {
                    "type": "integer",
                    "nullable": true,
                    "description": "スキャン実行時間の最大値（ミリ秒、直近 1024 サンプル内）"
                },
                "scan_avg_ms": {
                    "type": "integer",
                    "nullable": true,
                    "description": "スキャン実行時間の平均値（ミリ秒、直近 1024 サンプル内）"
                },
                "scan_p50_ms": {
                    "type": "integer",
                    "nullable": true,
                    "description": "スキャン実行時間の P50 中央値（ミリ秒）"
                },
                "scan_p95_ms": {
                    "type": "integer",
                    "nullable": true,
                    "description": "スキャン実行時間の P95 パーセンタイル（ミリ秒）"
                },
                "scan_p99_ms": {
                    "type": "integer",
                    "nullable": true,
                    "description": "スキャン実行時間の P99 パーセンタイル（ミリ秒）"
                }
            },
            "required": ["module", "events_total", "events_info", "events_warning", "events_critical"]
        },
        "ModulesResponse": {
            "type": "object",
            "properties": {
                "modules": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/ModuleInfo" },
                    "description": "モジュール一覧"
                }
            },
            "required": ["modules"]
        },
        "ModuleInfo": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "モジュール名"
                },
                "restarts": {
                    "type": "integer",
                    "description": "リスタート回数"
                }
            },
            "required": ["name", "restarts"]
        },
        "PaginatedEventsResponse": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/EventRecord" },
                    "description": "イベント一覧"
                },
                "next_cursor": {
                    "type": ["integer", "null"],
                    "description": "次ページのカーソル値（最終ページの場合は null）"
                },
                "has_more": {
                    "type": "boolean",
                    "description": "次のページが存在するか"
                },
                "count": {
                    "type": "integer",
                    "description": "返却件数"
                }
            },
            "required": ["items", "next_cursor", "has_more", "count"]
        },
        "EventRecord": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "integer",
                    "description": "イベント ID"
                },
                "timestamp": {
                    "type": "string",
                    "format": "date-time",
                    "description": "タイムスタンプ"
                },
                "severity": {
                    "type": "string",
                    "enum": ["info", "warning", "critical"],
                    "description": "重要度"
                },
                "source_module": {
                    "type": "string",
                    "description": "ソースモジュール名"
                },
                "event_type": {
                    "type": "string",
                    "description": "イベントタイプ"
                },
                "message": {
                    "type": "string",
                    "description": "メッセージ"
                },
                "details": {
                    "type": ["string", "null"],
                    "description": "詳細情報"
                },
                "acknowledged": {
                    "type": "boolean",
                    "description": "確認済みフラグ"
                }
            },
            "required": ["id", "timestamp", "severity", "source_module", "event_type", "message"]
        },
        "SecurityEvent": {
            "type": "object",
            "description": "WebSocket で送信されるセキュリティイベント",
            "properties": {
                "event_type": {
                    "type": "string",
                    "description": "イベントタイプ"
                },
                "severity": {
                    "type": "string",
                    "enum": ["info", "warning", "critical"],
                    "description": "重要度"
                },
                "source_module": {
                    "type": "string",
                    "description": "ソースモジュール名"
                },
                "timestamp": {
                    "type": "integer",
                    "description": "UNIX タイムスタンプ（秒）"
                },
                "message": {
                    "type": "string",
                    "description": "メッセージ"
                },
                "details": {
                    "type": ["string", "null"],
                    "description": "詳細情報"
                }
            },
            "required": ["event_type", "severity", "source_module", "timestamp", "message"]
        },
        "BatchDeleteRequest": {
            "type": "object",
            "description": "バッチ削除リクエスト。ids または filter のいずれかを指定する",
            "properties": {
                "ids": {
                    "type": "array",
                    "items": { "type": "integer", "format": "int64" },
                    "description": "削除対象のイベント ID 一覧"
                },
                "filter": { "$ref": "#/components/schemas/BatchDeleteFilter" }
            }
        },
        "BatchDeleteFilter": {
            "type": "object",
            "description": "バッチ削除フィルタ条件",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["info", "warning", "critical"],
                    "description": "Severity でフィルタリング"
                },
                "module": {
                    "type": "string",
                    "description": "ソースモジュール名でフィルタリング"
                },
                "since": {
                    "type": "string",
                    "format": "date-time",
                    "description": "開始日時（ISO 8601 形式）"
                },
                "until": {
                    "type": "string",
                    "format": "date-time",
                    "description": "終了日時（ISO 8601 形式）"
                }
            }
        },
        "BatchDeleteResponse": {
            "type": "object",
            "properties": {
                "deleted": {
                    "type": "integer",
                    "description": "削除された件数"
                }
            },
            "required": ["deleted"]
        },
        "BatchExportRequest": {
            "type": "object",
            "description": "バッチエクスポートリクエスト",
            "properties": {
                "filter": { "$ref": "#/components/schemas/BatchDeleteFilter" },
                "limit": {
                    "type": "integer",
                    "description": "最大取得件数（デフォルト: batch_max_size）",
                    "minimum": 1
                }
            }
        },
        "BatchExportResponse": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/EventRecord" },
                    "description": "エクスポートされたイベント一覧"
                },
                "count": {
                    "type": "integer",
                    "description": "エクスポートされた件数"
                }
            },
            "required": ["items", "count"]
        },
        "BatchAcknowledgeRequest": {
            "type": "object",
            "properties": {
                "ids": {
                    "type": "array",
                    "items": { "type": "integer", "format": "int64" },
                    "description": "確認済みにするイベント ID 一覧"
                }
            },
            "required": ["ids"]
        },
        "BatchAcknowledgeResponse": {
            "type": "object",
            "properties": {
                "acknowledged": {
                    "type": "integer",
                    "description": "確認済みにした件数"
                }
            },
            "required": ["acknowledged"]
        },
        "DryRunBatchResponse": {
            "type": "object",
            "description": "バッチ操作の dry-run レスポンス（削除・確認済みマーク共通）",
            "properties": {
                "dry_run": {
                    "type": "boolean",
                    "enum": [true],
                    "description": "dry-run モードであることを示すフラグ"
                },
                "affected_count": {
                    "type": "integer",
                    "description": "影響を受けるイベント件数"
                },
                "details": {
                    "type": "object",
                    "properties": {
                        "sample_ids": {
                            "type": "array",
                            "items": { "type": "integer", "format": "int64" },
                            "description": "影響を受けるイベント ID のサンプル（最大10件）"
                        }
                    },
                    "required": ["sample_ids"]
                }
            },
            "required": ["dry_run", "affected_count", "details"]
        },
        "DryRunReloadResponse": {
            "type": "object",
            "description": "リロード dry-run レスポンス（設定ファイルバリデーション結果）",
            "properties": {
                "dry_run": {
                    "type": "boolean",
                    "enum": [true],
                    "description": "dry-run モードであることを示すフラグ"
                },
                "message": {
                    "type": "string",
                    "description": "バリデーション結果メッセージ"
                },
                "details": {
                    "type": "object",
                    "properties": {
                        "config_valid": {
                            "type": "boolean",
                            "description": "設定ファイルが有効かどうか"
                        },
                        "errors": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "バリデーションエラーの一覧（有効な場合は空配列）"
                        }
                    },
                    "required": ["config_valid", "errors"]
                }
            },
            "required": ["dry_run", "message", "details"]
        },
        "SecurityScore": {
            "type": "object",
            "properties": {
                "overall_score": {
                    "type": "integer",
                    "description": "総合セキュリティスコア（0〜100）",
                    "minimum": 0,
                    "maximum": 100
                },
                "grade": {
                    "type": "string",
                    "description": "グレード（A〜F）",
                    "enum": ["A", "B", "C", "D", "F"]
                },
                "categories": {
                    "type": "object",
                    "description": "カテゴリ別スコア",
                    "additionalProperties": { "$ref": "#/components/schemas/CategoryScore" }
                },
                "summary": { "$ref": "#/components/schemas/ScoreSummary" },
                "evaluated_at": {
                    "type": "string",
                    "format": "date-time",
                    "description": "評価日時（ISO 8601）"
                }
            },
            "required": ["overall_score", "grade", "categories", "summary", "evaluated_at"]
        },
        "CategoryScore": {
            "type": "object",
            "properties": {
                "score": {
                    "type": "integer",
                    "description": "カテゴリスコア（0〜100）",
                    "minimum": 0,
                    "maximum": 100
                },
                "grade": {
                    "type": "string",
                    "description": "グレード（A〜F）"
                },
                "issues": {
                    "type": "integer",
                    "description": "検知された問題数"
                }
            },
            "required": ["score", "grade", "issues"]
        },
        "ScoreSummary": {
            "type": "object",
            "properties": {
                "total_events": { "type": "integer", "description": "総イベント数" },
                "critical": { "type": "integer", "description": "CRITICAL イベント数" },
                "high": { "type": "integer", "description": "HIGH（WARNING）イベント数" },
                "medium": { "type": "integer", "description": "MEDIUM イベント数（0固定）" },
                "low": { "type": "integer", "description": "LOW イベント数（0固定）" },
                "info": { "type": "integer", "description": "INFO イベント数" }
            },
            "required": ["total_events", "critical", "high", "medium", "low", "info"]
        },
        "ArchiveInfo": {
            "type": "object",
            "properties": {
                "filename": { "type": "string", "description": "アーカイブファイル名" },
                "size": { "type": "integer", "description": "ファイルサイズ（バイト）" },
                "checksum": { "type": ["string", "null"], "description": "SHA-256 チェックサム" },
                "created_at": { "type": ["integer", "null"], "description": "作成日時（UNIX タイムスタンプ秒）" }
            },
            "required": ["filename", "size"]
        },
        "ArchiveListResponse": {
            "type": "object",
            "properties": {
                "archives": {
                    "type": "array",
                    "items": { "$ref": "#/components/schemas/ArchiveInfo" },
                    "description": "アーカイブファイル一覧"
                },
                "count": { "type": "integer", "description": "アーカイブファイル数" }
            },
            "required": ["archives", "count"]
        },
        "ArchiveCreateRequest": {
            "type": "object",
            "description": "手動アーカイブリクエスト（省略時はデフォルト設定を使用）",
            "properties": {
                "archive_after_days": { "type": "integer", "description": "アーカイブ対象とするイベントの経過日数" },
                "compress": { "type": "boolean", "description": "gzip 圧縮の有効/無効" }
            }
        },
        "ArchiveCreateResponse": {
            "type": "object",
            "properties": {
                "message": { "type": "string", "description": "結果メッセージ" },
                "archived": { "type": "integer", "description": "アーカイブされたイベント数" }
            },
            "required": ["message"]
        },
        "ArchiveRestoreRequest": {
            "type": "object",
            "properties": {
                "filename": { "type": "string", "description": "復元するアーカイブファイル名" }
            },
            "required": ["filename"]
        },
        "ArchiveRestoreResponse": {
            "type": "object",
            "properties": {
                "message": { "type": "string", "description": "結果メッセージ" },
                "restored": { "type": "integer", "description": "復元されたイベント数" }
            },
            "required": ["message"]
        },
        "ArchiveRotateRequest": {
            "type": "object",
            "description": "ローテーションリクエスト（省略時はデフォルト設定を使用）",
            "properties": {
                "max_age_days": { "type": "integer", "description": "最大保持日数（0 で無制限）" },
                "max_total_mb": { "type": "integer", "description": "合計サイズ上限（MB、0 で無制限）" },
                "max_files": { "type": "integer", "description": "最大保持ファイル数（0 で無制限）" }
            }
        },
        "ArchiveRotateResponse": {
            "type": "object",
            "properties": {
                "message": { "type": "string", "description": "結果メッセージ" },
                "deleted": { "type": "integer", "description": "削除されたファイル数" }
            },
            "required": ["message"]
        },
        "ArchiveDeleteResponse": {
            "type": "object",
            "properties": {
                "message": { "type": "string", "description": "結果メッセージ" },
                "filename": { "type": "string", "description": "削除されたファイル名" }
            },
            "required": ["message", "filename"]
        },
        "WebhookInfo": {
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Webhook 名" },
                "action_type": { "type": "string", "enum": ["rule", "digest"], "description": "Webhook 種別" },
                "severity_filter": { "type": "string", "nullable": true, "description": "Severity フィルタ" },
                "module_filter": { "type": "string", "nullable": true, "description": "モジュール名フィルタ" },
                "url_masked": { "type": "string", "description": "マスク済み URL" },
                "method": { "type": "string", "description": "HTTP メソッド" },
                "has_headers": { "type": "boolean", "description": "カスタムヘッダーの有無" },
                "has_body_template": { "type": "boolean", "description": "ボディテンプレートの有無" },
                "max_retries": { "type": "integer", "description": "最大リトライ回数" },
                "timeout_secs": { "type": "integer", "nullable": true, "description": "タイムアウト秒数" }
            }
        },
        "ModuleControlResponse": {
            "type": "object",
            "properties": {
                "success": { "type": "boolean", "description": "操作成功か" },
                "module": { "type": "string", "description": "モジュール名" },
                "action": { "type": "string", "enum": ["start", "stop", "restart"], "description": "実行されたアクション" },
                "message": { "type": "string", "description": "結果メッセージ" }
            },
            "required": ["success", "module", "action", "message"]
        },
        "WebhookTestResult": {
            "type": "object",
            "properties": {
                "success": { "type": "boolean", "description": "送信成功か" },
                "name": { "type": "string", "description": "Webhook 名" },
                "url_masked": { "type": "string", "description": "マスク済み URL" },
                "status_code": { "type": "integer", "description": "HTTP ステータスコード" },
                "response_time_ms": { "type": "integer", "description": "応答時間（ミリ秒）" },
                "error": { "type": "string", "description": "エラーメッセージ（失敗時のみ）" }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_openapi_schema_has_required_fields() {
        let schema = generate_openapi_schema();
        assert_eq!(schema["openapi"], "3.0.3");
        assert!(schema["info"]["title"].is_string());
        assert!(schema["info"]["version"].is_string());
        assert!(schema["paths"].is_object());
        assert!(schema["components"].is_object());
    }

    #[test]
    fn test_all_endpoints_present() {
        let schema = generate_openapi_schema();
        let paths = schema["paths"].as_object().unwrap();
        assert!(paths.contains_key("/api/v1/health"));
        assert!(paths.contains_key("/api/v1/status"));
        assert!(paths.contains_key("/api/v1/modules"));
        assert!(paths.contains_key("/api/v1/events"));
        assert!(paths.contains_key("/api/v1/reload"));
        assert!(paths.contains_key("/api/v1/events/stream"));
        assert!(paths.contains_key("/api/v1/openapi.json"));
        assert!(paths.contains_key("/api/v1/modules/{name}/start"));
        assert!(paths.contains_key("/api/v1/modules/{name}/stop"));
        assert!(paths.contains_key("/api/v1/modules/{name}/restart"));
    }

    #[test]
    fn test_security_scheme_defined() {
        let schema = generate_openapi_schema();
        let schemes = &schema["components"]["securitySchemes"];
        assert!(schemes["BearerAuth"].is_object());
        assert_eq!(schemes["BearerAuth"]["type"], "http");
        assert_eq!(schemes["BearerAuth"]["scheme"], "bearer");
    }

    #[test]
    fn test_component_schemas_defined() {
        let schema = generate_openapi_schema();
        let schemas = &schema["components"]["schemas"];
        assert!(schemas["StatusResponse"].is_object());
        assert!(schemas["MetricsSummary"].is_object());
        assert!(schemas["ModulesResponse"].is_object());
        assert!(schemas["PaginatedEventsResponse"].is_object());
        assert!(schemas["EventRecord"].is_object());
        assert!(schemas["SecurityEvent"].is_object());
        assert!(schemas["ErrorResponse"].is_object());
    }

    #[test]
    fn test_health_endpoint_no_auth() {
        let schema = generate_openapi_schema();
        let health = &schema["paths"]["/api/v1/health"]["get"];
        assert!(health["security"].is_null());
    }

    #[test]
    fn test_status_endpoint_requires_auth() {
        let schema = generate_openapi_schema();
        let status = &schema["paths"]["/api/v1/status"]["get"];
        assert!(status["security"].is_array());
    }

    #[test]
    fn test_events_query_parameters() {
        let schema = generate_openapi_schema();
        let events = &schema["paths"]["/api/v1/events"]["get"];
        let params = events["parameters"].as_array().unwrap();
        assert_eq!(params.len(), 7);
        let param_names: Vec<&str> = params.iter().map(|p| p["name"].as_str().unwrap()).collect();
        assert!(param_names.contains(&"q"));
        assert!(param_names.contains(&"severity"));
        assert!(param_names.contains(&"module"));
        assert!(param_names.contains(&"since"));
        assert!(param_names.contains(&"until"));
        assert!(param_names.contains(&"limit"));
        assert!(param_names.contains(&"cursor"));
    }

    #[test]
    fn test_reload_is_post() {
        let schema = generate_openapi_schema();
        assert!(schema["paths"]["/api/v1/reload"]["post"].is_object());
        assert!(schema["paths"]["/api/v1/reload"]["get"].is_null());
    }

    #[test]
    fn test_paginated_events_response_schema() {
        let schema = generate_openapi_schema();
        let paginated = &schema["components"]["schemas"]["PaginatedEventsResponse"];
        assert!(paginated.is_object());

        let props = paginated["properties"].as_object().unwrap();
        assert!(props.contains_key("items"));
        assert!(props.contains_key("next_cursor"));
        assert!(props.contains_key("has_more"));
        assert!(props.contains_key("count"));

        let required = paginated["required"].as_array().unwrap();
        let required_names: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_names.contains(&"items"));
        assert!(required_names.contains(&"next_cursor"));
        assert!(required_names.contains(&"has_more"));
        assert!(required_names.contains(&"count"));
    }

    #[test]
    fn test_batch_endpoints_present() {
        let schema = generate_openapi_schema();
        let paths = schema["paths"].as_object().unwrap();
        assert!(paths.contains_key("/api/v1/events/batch/delete"));
        assert!(paths.contains_key("/api/v1/events/batch/export"));
        assert!(paths.contains_key("/api/v1/events/batch/acknowledge"));
    }

    #[test]
    fn test_batch_schemas_defined() {
        let schema = generate_openapi_schema();
        let schemas = &schema["components"]["schemas"];
        assert!(schemas["BatchDeleteRequest"].is_object());
        assert!(schemas["BatchDeleteFilter"].is_object());
        assert!(schemas["BatchDeleteResponse"].is_object());
        assert!(schemas["BatchExportRequest"].is_object());
        assert!(schemas["BatchExportResponse"].is_object());
        assert!(schemas["BatchAcknowledgeRequest"].is_object());
        assert!(schemas["BatchAcknowledgeResponse"].is_object());
    }

    #[test]
    fn test_openapi_schema_is_valid_json() {
        let schema = generate_openapi_schema();
        let json_str = serde_json::to_string(&schema).unwrap();
        assert!(!json_str.is_empty());
        let reparsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(schema, reparsed);
    }
}
