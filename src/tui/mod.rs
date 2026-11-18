//! Ratatui v0.30+ 3-pane interactive Faraday Cage Monitor (`faraday tui`).

pub mod ui;

use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::vault::{RedactionAuditEvent, SecretMetadata};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePane {
    Secrets,
    RedactionLog,
}

pub struct FaradayTuiApp {
    pub vault_path: String,
    pub secrets: Vec<SecretMetadata>,
    pub events: Vec<RedactionAuditEvent>,
    pub active_pane: ActivePane,
    pub selected_secret: usize,
    pub selected_event: usize,
}

impl FaradayTuiApp {
    pub fn new(
        vault_path: String,
        secrets: Vec<SecretMetadata>,
        events: Vec<RedactionAuditEvent>,
    ) -> Self {
        Self {
            vault_path,
            secrets,
            events,
            active_pane: ActivePane::Secrets,
            selected_secret: 0,
            selected_event: 0,
        }
    }

    pub fn toggle_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::Secrets => ActivePane::RedactionLog,
            ActivePane::RedactionLog => ActivePane::Secrets,
        };
    }

    pub fn move_down(&mut self) {
        match self.active_pane {
            ActivePane::Secrets => {
                if !self.secrets.is_empty() {
                    self.selected_secret = (self.selected_secret + 1) % self.secrets.len();
                }
            }
            ActivePane::RedactionLog => {
                if !self.events.is_empty() {
                    self.selected_event = (self.selected_event + 1) % self.events.len();
                }
            }
        }
    }

    pub fn move_up(&mut self) {
        match self.active_pane {
            ActivePane::Secrets => {
                if !self.secrets.is_empty() {
                    self.selected_secret = self
                        .selected_secret
                        .checked_sub(1)
                        .unwrap_or(self.secrets.len() - 1);
                }
            }
            ActivePane::RedactionLog => {
                if !self.events.is_empty() {
                    self.selected_event = self
                        .selected_event
                        .checked_sub(1)
                        .unwrap_or(self.events.len() - 1);
                }
            }
        }
    }
}

pub fn run_interactive_tui(mut app: FaradayTuiApp) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = (|| -> Result<()> {
        loop {
            terminal.draw(|frame| ui::render(frame, &app))?;
            if event::poll(Duration::from_millis(100))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Tab => app.toggle_pane(),
                    KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                    KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}
