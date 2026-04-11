//! CLI ダッシュボード（TUI）— ratatui ベースのリアルタイム監視ダッシュボード

use crate::core::status::{self, StatusResponse};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

const MAX_EVENTS: usize = 200;

/// TUI で表示するイベント
#[derive(Debug, Clone)]
struct DashboardEvent {
    severity: String,
    source_module: String,
    event_type: String,
    message: String,
}

/// アクティブなパネル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivePanel {
    Modules,
    Events,
    Metrics,
}

impl ActivePanel {
    fn next(self) -> Self {
        match self {
            ActivePanel::Modules => ActivePanel::Events,
            ActivePanel::Events => ActivePanel::Metrics,
            ActivePanel::Metrics => ActivePanel::Modules,
        }
    }
}

/// バックグラウンドタスクから TUI スレッドへ送るメッセージ
enum AppMessage {
    StatusUpdate(StatusResponse),
    StatusError,
    NewEvent(DashboardEvent),
    EventStreamConnected,
    EventStreamDisconnected,
}

/// TUI アプリケーション状態
struct App {
    status: Option<StatusResponse>,
    connected: bool,
    event_stream_connected: bool,
    events: VecDeque<DashboardEvent>,
    active_panel: ActivePanel,
    module_scroll: usize,
    event_scroll: usize,
    metrics_scroll: usize,
    should_quit: bool,
}

impl App {
    fn new() -> Self {
        Self {
            status: None,
            connected: false,
            event_stream_connected: false,
            events: VecDeque::with_capacity(MAX_EVENTS),
            active_panel: ActivePanel::Modules,
            module_scroll: 0,
            event_scroll: 0,
            metrics_scroll: 0,
            should_quit: false,
        }
    }

    fn push_event(&mut self, event: DashboardEvent) {
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    fn update_status(&mut self, response: StatusResponse) {
        self.status = Some(response);
        self.connected = true;
    }

    fn scroll_up(&mut self) {
        match self.active_panel {
            ActivePanel::Modules => self.module_scroll = self.module_scroll.saturating_sub(1),
            ActivePanel::Events => self.event_scroll = self.event_scroll.saturating_sub(1),
            ActivePanel::Metrics => self.metrics_scroll = self.metrics_scroll.saturating_sub(1),
        }
    }

    fn scroll_down(&mut self) {
        match self.active_panel {
            ActivePanel::Modules => self.module_scroll = self.module_scroll.saturating_add(1),
            ActivePanel::Events => self.event_scroll = self.event_scroll.saturating_add(1),
            ActivePanel::Metrics => self.metrics_scroll = self.metrics_scroll.saturating_add(1),
        }
    }
}

struct DashboardLayout {
    header: Rect,
    modules: Rect,
    events: Rect,
    metrics: Rect,
    footer: Rect,
}

fn build_layout(area: Rect) -> DashboardLayout {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(area);

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(outer[1]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(main[1]);

    DashboardLayout {
        header: outer[0],
        modules: main[0],
        events: right[0],
        metrics: right[1],
        footer: outer[2],
    }
}

/// ダッシュボードを起動する
pub async fn run_dashboard(
    status_socket: impl AsRef<Path>,
    event_stream_socket: impl AsRef<Path>,
) -> Result<(), String> {
    let (tx, rx) = mpsc::unbounded_channel();

    let status_path = status_socket.as_ref().to_path_buf();
    let tx_status = tx.clone();
    tokio::spawn(async move {
        status_polling_task(status_path, tx_status).await;
    });

    let event_path = event_stream_socket.as_ref().to_path_buf();
    let tx_events = tx;
    tokio::spawn(async move {
        event_stream_task(event_path, tx_events).await;
    });

    let mut terminal = ratatui::init();
    let result = run_app(&mut terminal, rx);
    ratatui::restore();
    result
}

fn run_app(
    terminal: &mut ratatui::DefaultTerminal,
    mut rx: mpsc::UnboundedReceiver<AppMessage>,
) -> Result<(), String> {
    let mut app = App::new();

    loop {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                AppMessage::StatusUpdate(resp) => app.update_status(resp),
                AppMessage::StatusError => app.connected = false,
                AppMessage::NewEvent(ev) => app.push_event(ev),
                AppMessage::EventStreamConnected => app.event_stream_connected = true,
                AppMessage::EventStreamDisconnected => app.event_stream_connected = false,
            }
        }

        terminal
            .draw(|frame| render(frame, &app))
            .map_err(|e| format!("描画エラー: {}", e))?;

        if event::poll(std::time::Duration::from_millis(100))
            .map_err(|e| format!("イベントポーリングエラー: {}", e))?
            && let Event::Key(key) =
                event::read().map_err(|e| format!("キーイベント読み取りエラー: {}", e))?
            && key.kind == KeyEventKind::Press
        {
            handle_key(&mut app, key.code);
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn handle_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Tab => app.active_panel = app.active_panel.next(),
        KeyCode::Up => app.scroll_up(),
        KeyCode::Down => app.scroll_down(),
        _ => {}
    }
}

async fn status_polling_task(socket_path: PathBuf, tx: mpsc::UnboundedSender<AppMessage>) {
    loop {
        match status::query_status(&socket_path).await {
            Ok(response) => {
                if tx.send(AppMessage::StatusUpdate(response)).is_err() {
                    break;
                }
            }
            Err(_) => {
                if tx.send(AppMessage::StatusError).is_err() {
                    break;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn event_stream_task(socket_path: PathBuf, tx: mpsc::UnboundedSender<AppMessage>) {
    use tokio::io::AsyncBufReadExt;
    use tokio::net::UnixStream;

    loop {
        match UnixStream::connect(&socket_path).await {
            Ok(stream) => {
                let _ = tx.send(AppMessage::EventStreamConnected);
                let reader = tokio::io::BufReader::new(stream);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&line) {
                        let event = DashboardEvent {
                            severity: parsed
                                .get("severity")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?")
                                .to_string(),
                            source_module: parsed
                                .get("source_module")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?")
                                .to_string(),
                            event_type: parsed
                                .get("event_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?")
                                .to_string(),
                            message: parsed
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                        };
                        if tx.send(AppMessage::NewEvent(event)).is_err() {
                            return;
                        }
                    }
                }
                let _ = tx.send(AppMessage::EventStreamDisconnected);
            }
            Err(_) => {
                let _ = tx.send(AppMessage::EventStreamDisconnected);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

fn render(frame: &mut Frame, app: &App) {
    let layout = build_layout(frame.area());
    render_header(frame, &layout, app);
    render_modules(frame, &layout, app);
    render_events(frame, &layout, app);
    render_metrics(frame, &layout, app);
    render_footer(frame, &layout, app);
}

fn render_header(frame: &mut Frame, layout: &DashboardLayout, app: &App) {
    let version = app
        .status
        .as_ref()
        .map(|s| s.version.clone())
        .unwrap_or_else(|| "---".to_string());
    let uptime = app
        .status
        .as_ref()
        .map(|s| format_uptime(s.uptime_secs))
        .unwrap_or_else(|| "---".to_string());
    let status_indicator = if app.connected { "●" } else { "○" };
    let status_color = if app.connected {
        Color::Green
    } else {
        Color::Red
    };
    let event_indicator = if app.event_stream_connected {
        "●"
    } else {
        "○"
    };
    let event_color = if app.event_stream_connected {
        Color::Green
    } else {
        Color::Red
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" ぜったいまもるくん v{}", version),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  |  稼働: "),
        Span::raw(uptime),
        Span::raw("  |  ステータス: "),
        Span::styled(status_indicator, Style::default().fg(status_color)),
        Span::raw("  イベント: "),
        Span::styled(event_indicator, Style::default().fg(event_color)),
    ]))
    .block(Block::default().borders(Borders::ALL));

    frame.render_widget(header, layout.header);
}

fn render_modules(frame: &mut Frame, layout: &DashboardLayout, app: &App) {
    let border_style = if app.active_panel == ActivePanel::Modules {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let modules = app
        .status
        .as_ref()
        .map(|s| s.modules.clone())
        .unwrap_or_default();

    let module_count = modules.len();
    let visible_height = layout.modules.height.saturating_sub(2) as usize;
    let max_scroll = module_count.saturating_sub(visible_height);
    let scroll = app.module_scroll.min(max_scroll);

    let items: Vec<ListItem> = modules
        .iter()
        .skip(scroll)
        .take(visible_height)
        .map(|m| {
            let restart_count = app
                .status
                .as_ref()
                .and_then(|s| s.module_restarts.get(m))
                .copied()
                .unwrap_or(0);
            let suffix = if restart_count > 0 {
                format!(" (再起動: {}回)", restart_count)
            } else {
                String::new()
            };
            ListItem::new(format!("● {}{}", m, suffix)).style(Style::default().fg(Color::Green))
        })
        .collect();

    let title = format!("モジュール ({})", module_count);
    let list = List::new(items).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(list, layout.modules);
}

fn render_events(frame: &mut Frame, layout: &DashboardLayout, app: &App) {
    let border_style = if app.active_panel == ActivePanel::Events {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let visible_height = layout.events.height.saturating_sub(2) as usize;
    let total = app.events.len();
    let max_scroll = total.saturating_sub(visible_height);
    let scroll = app.event_scroll.min(max_scroll);

    let items: Vec<ListItem> = app
        .events
        .iter()
        .rev()
        .skip(scroll)
        .take(visible_height)
        .map(|ev| {
            let (severity_style, severity_label) = match ev.severity.as_str() {
                "CRITICAL" => (
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    "CRIT",
                ),
                "WARNING" => (Style::default().fg(Color::Yellow), "WARN"),
                _ => (Style::default().fg(Color::Blue), "INFO"),
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("[{}]", severity_label), severity_style),
                Span::raw(format!(
                    " {} ({}): {}",
                    ev.event_type, ev.source_module, ev.message
                )),
            ]))
        })
        .collect();

    let title = format!("イベント ({})", total);
    let list = List::new(items).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(list, layout.events);
}

fn render_metrics(frame: &mut Frame, layout: &DashboardLayout, app: &App) {
    let border_style = if app.active_panel == ActivePanel::Metrics {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let visible_height = layout.metrics.height.saturating_sub(2) as usize;

    let lines = if let Some(metrics) = app.status.as_ref().and_then(|s| s.metrics.as_ref()) {
        let mut lines = vec![
            Line::from(vec![
                Span::raw("合計: "),
                Span::styled(
                    metrics.total_events.to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("INFO: {}", metrics.info_count),
                    Style::default().fg(Color::Blue),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("WARNING: {}", metrics.warning_count),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("CRITICAL: {}", metrics.critical_count),
                    Style::default().fg(Color::Red),
                ),
            ]),
            Line::raw(""),
            Line::raw("モジュール別上位:"),
        ];

        let mut sorted: Vec<_> = metrics.module_counts.iter().collect();
        sorted.sort_by_key(|(_, v)| std::cmp::Reverse(**v));
        for (module, count) in sorted.iter().take(10) {
            lines.push(Line::from(format!("  {}: {}", module, count)));
        }

        lines
    } else {
        vec![Line::raw(
            "メトリクスデータなし（デーモン未接続または無効）",
        )]
    };

    let max_scroll_offset = lines.len().saturating_sub(visible_height);
    let scroll = app.metrics_scroll.min(max_scroll_offset);

    let paragraph = Paragraph::new(lines).scroll((scroll as u16, 0)).block(
        Block::default()
            .title("メトリクス")
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(paragraph, layout.metrics);
}

fn render_footer(frame: &mut Frame, layout: &DashboardLayout, app: &App) {
    let active_name = match app.active_panel {
        ActivePanel::Modules => "モジュール",
        ActivePanel::Events => "イベント",
        ActivePanel::Metrics => "メトリクス",
    };
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" [Tab]", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" パネル切替  "),
        Span::styled("[↑↓]", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" スクロール  "),
        Span::styled("[q]", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" 終了  "),
        Span::raw(format!("| 選択: {}", active_name)),
    ]))
    .style(Style::default().fg(Color::DarkGray));

    frame.render_widget(footer, layout.footer);
}

fn format_uptime(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::status::MetricsSummary;
    use std::collections::HashMap;

    #[test]
    fn test_app_new() {
        let app = App::new();
        assert!(app.status.is_none());
        assert!(!app.connected);
        assert!(!app.event_stream_connected);
        assert!(app.events.is_empty());
        assert_eq!(app.active_panel, ActivePanel::Modules);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_push_event_within_limit() {
        let mut app = App::new();
        for i in 0..10 {
            app.push_event(DashboardEvent {
                severity: "INFO".to_string(),
                source_module: "test".to_string(),
                event_type: format!("event_{}", i),
                message: "test".to_string(),
            });
        }
        assert_eq!(app.events.len(), 10);
    }

    #[test]
    fn test_push_event_overflow() {
        let mut app = App::new();
        for i in 0..MAX_EVENTS + 10 {
            app.push_event(DashboardEvent {
                severity: "INFO".to_string(),
                source_module: "test".to_string(),
                event_type: format!("event_{}", i),
                message: "test".to_string(),
            });
        }
        assert_eq!(app.events.len(), MAX_EVENTS);
        assert_eq!(
            app.events.front().map(|e| e.event_type.as_str()),
            Some("event_10")
        );
    }

    #[test]
    fn test_update_status() {
        let mut app = App::new();
        assert!(!app.connected);

        app.update_status(StatusResponse {
            version: "1.6.0".to_string(),
            uptime_secs: 100,
            modules: vec!["mod_a".to_string()],
            metrics: None,
            module_restarts: HashMap::new(),
        });

        assert!(app.connected);
        assert!(app.status.is_some());
        assert_eq!(app.status.as_ref().map(|s| s.uptime_secs), Some(100));
    }

    #[test]
    fn test_active_panel_cycle() {
        assert_eq!(ActivePanel::Modules.next(), ActivePanel::Events);
        assert_eq!(ActivePanel::Events.next(), ActivePanel::Metrics);
        assert_eq!(ActivePanel::Metrics.next(), ActivePanel::Modules);
    }

    #[test]
    fn test_scroll() {
        let mut app = App::new();
        app.active_panel = ActivePanel::Modules;

        app.scroll_down();
        assert_eq!(app.module_scroll, 1);
        app.scroll_down();
        assert_eq!(app.module_scroll, 2);
        app.scroll_up();
        assert_eq!(app.module_scroll, 1);
        app.scroll_up();
        assert_eq!(app.module_scroll, 0);
        app.scroll_up();
        assert_eq!(app.module_scroll, 0);
    }

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(59), "59s");
        assert_eq!(format_uptime(60), "1m 0s");
        assert_eq!(format_uptime(3661), "1h 1m 1s");
        assert_eq!(format_uptime(7200), "2h 0m 0s");
    }

    #[test]
    fn test_build_layout() {
        let area = Rect::new(0, 0, 120, 40);
        let layout = build_layout(area);

        assert_eq!(layout.header.height, 3);
        assert_eq!(layout.footer.height, 1);
        assert!(layout.modules.width > 0);
        assert!(layout.events.width > 0);
        assert!(layout.metrics.width > 0);
    }

    #[test]
    fn test_render_does_not_panic() {
        let backend = ratatui::backend::TestBackend::new(120, 40);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal creation");

        let mut app = App::new();
        app.update_status(StatusResponse {
            version: "1.7.0".to_string(),
            uptime_secs: 3600,
            modules: vec!["module_a".to_string(), "module_b".to_string()],
            metrics: Some(MetricsSummary {
                total_events: 100,
                info_count: 80,
                warning_count: 15,
                critical_count: 5,
                module_counts: HashMap::from([("module_a".to_string(), 60)]),
            }),
            module_restarts: HashMap::from([("module_b".to_string(), 2)]),
        });

        app.push_event(DashboardEvent {
            severity: "CRITICAL".to_string(),
            source_module: "module_a".to_string(),
            event_type: "file_modified".to_string(),
            message: "test critical event".to_string(),
        });
        app.push_event(DashboardEvent {
            severity: "WARNING".to_string(),
            source_module: "module_b".to_string(),
            event_type: "process_anomaly".to_string(),
            message: "test warning event".to_string(),
        });
        app.push_event(DashboardEvent {
            severity: "INFO".to_string(),
            source_module: "module_a".to_string(),
            event_type: "scan_complete".to_string(),
            message: "test info event".to_string(),
        });

        terminal.draw(|frame| render(frame, &app)).unwrap();
    }

    #[test]
    fn test_render_disconnected_state() {
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal creation");

        let app = App::new();
        terminal.draw(|frame| render(frame, &app)).unwrap();
    }

    #[test]
    fn test_render_with_active_panels() {
        let backend = ratatui::backend::TestBackend::new(120, 40);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal creation");

        let mut app = App::new();
        app.active_panel = ActivePanel::Events;
        terminal.draw(|frame| render(frame, &app)).unwrap();

        app.active_panel = ActivePanel::Metrics;
        terminal.draw(|frame| render(frame, &app)).unwrap();
    }
}
