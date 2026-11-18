//! Ratatui v0.30+ layout and ANSI/OSC escape-sanitized renderer (`CWE-150`) for **Faraday**.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::tui::{ActivePane, FaradayTuiApp};

/// Strip C0/C1 control characters and ANSI/OSC escape sequences (`\x1b`) before rendering
/// untrusted command strings or key names into the terminal buffer (`CWE-150`).
pub fn sanitize_terminal_str(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || (!c.is_control() && c != '\u{001b}'))
        .collect()
}

pub fn render(frame: &mut Frame, app: &FaradayTuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Percentage(52),
            Constraint::Percentage(38),
            Constraint::Length(2),
        ])
        .split(frame.area());

    // 1. Masthead Banner
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " FARADAY v0.1.0 ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" // "),
        Span::styled(
            "ZERO-DISK PROCESS SECRET INJECTOR & 4-ENCODING REDACTION CAGE  ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " TWO-TIER AEAD: LOCKED ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    // 2. Telemetry Strip
    let meta_text = format!(
        "SQLite WAL Vault: {}   |   Scoped Secrets: {}   |   Intercepted Leaks: {}\nEnvelope: Argon2id + HKDF-SHA256 + Two-Tier XChaCha20-Poly1305 (Per-Secret DEK)",
        sanitize_terminal_str(&app.vault_path),
        app.secrets.len(),
        app.events.len()
    );
    let meta_pane = Paragraph::new(meta_text).block(
        Block::default()
            .title(" [00] VAULT & FARADAY CAGE TELEMETRY ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(meta_pane, chunks[1]);

    // 3. Scoped Secrets Metadata Table (Plaintext values NEVER rendered)
    let sec_border = if app.active_pane == ActivePane::Secrets {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let sec_header = Row::new(
        [
            "SCOPE",
            "VARIABLE KEY",
            "VALUE STATUS",
            "BLAKE3 TAG",
            "UPDATED AT",
        ]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        }),
    )
    .height(1);

    let sec_rows = app.secrets.iter().enumerate().map(|(idx, s)| {
        let row_style = if idx == app.selected_secret {
            Style::default().bg(Color::DarkGray)
        } else {
            Style::default()
        };
        Row::new(vec![
            Cell::from(sanitize_terminal_str(&s.scope)),
            Cell::from(sanitize_terminal_str(&s.key_name)),
            Cell::from("[AEAD SEALED // ZERO-DISK]").style(
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from(sanitize_terminal_str(&s.blake3_tag)),
            Cell::from(sanitize_terminal_str(&s.updated_at)),
        ])
        .style(row_style)
    });

    let sec_table = Table::new(
        sec_rows,
        [
            Constraint::Length(14),
            Constraint::Length(26),
            Constraint::Length(28),
            Constraint::Length(14),
            Constraint::Percentage(30),
        ],
    )
    .header(sec_header)
    .block(
        Block::default()
            .title(" [01] SCOPED SECRET METADATA (VALUES MASKED) ")
            .borders(Borders::ALL)
            .border_style(sec_border),
    );
    frame.render_widget(sec_table, chunks[2]);

    // 4. Intercepted Stream Redaction Audit Log
    let log_border = if app.active_pane == ActivePane::RedactionLog {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let log_header = Row::new(
        [
            "ID",
            "SCOPE",
            "STREAM",
            "KEY",
            "ENCODING",
            "BLAKE3 TAG",
            "COMMAND",
        ]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        }),
    )
    .height(1);

    let log_rows = app.events.iter().enumerate().map(|(idx, ev)| {
        let row_style = if idx == app.selected_event {
            Style::default().bg(Color::DarkGray)
        } else {
            Style::default()
        };
        Row::new(vec![
            Cell::from(ev.id.to_string()),
            Cell::from(sanitize_terminal_str(&ev.scope)),
            Cell::from(sanitize_terminal_str(&ev.stream)),
            Cell::from(sanitize_terminal_str(&ev.key_name))
                .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Cell::from(sanitize_terminal_str(&ev.encoding_matched)),
            Cell::from(sanitize_terminal_str(&ev.blake3_tag)),
            Cell::from(sanitize_terminal_str(&ev.command)),
        ])
        .style(row_style)
    });

    let log_table = Table::new(
        log_rows,
        [
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(22),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Percentage(35),
        ],
    )
    .header(log_header)
    .block(
        Block::default()
            .title(" [02] INTERCEPTED STDOUT/STDERR LEAK REDACTION EVENTS ")
            .borders(Borders::ALL)
            .border_style(log_border),
    );
    frame.render_widget(log_table, chunks[3]);

    // 5. Footer
    let footer =
        Paragraph::new(" [Tab] Switch Pane   [j/k] Navigate   [q / Esc] Quit Faraday Cage Monitor")
            .style(Style::default().fg(Color::Gray));
    frame.render_widget(footer, chunks[4]);
}
