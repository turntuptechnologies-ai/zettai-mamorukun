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
            "description": "設定ファイルを再読み込みし、変更のあったモジュールを再起動する。admin ロールが必要。",
            "operationId": "postReload",
            "tags": ["system"],
            "security": [{"BearerAuth": []}],
            "responses": {
                "200": {
                    "description": "リロード成功",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "message": {
                                        "type": "string",
                                        "example": "リロードをトリガーしました"
                                    }
                                },
                                "required": ["message"]
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
            "description": "ID 指定またはフィルタ条件でイベントを一括削除する。admin ロールが必要。",
            "operationId": "postBatchDelete",
            "tags": ["events"],
            "security": [{"BearerAuth": []}],
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
                    "description": "削除成功",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/BatchDeleteResponse" }
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
            "description": "ID 指定でイベントを一括確認済みにする。admin ロールが必要。",
            "operationId": "postBatchAcknowledge",
            "tags": ["events"],
            "security": [{"BearerAuth": []}],
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
                    "description": "確認済みマーク成功",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/BatchAcknowledgeResponse" }
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
        assert_eq!(params.len(), 6);
        let param_names: Vec<&str> = params.iter().map(|p| p["name"].as_str().unwrap()).collect();
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
