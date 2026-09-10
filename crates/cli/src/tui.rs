use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use lusby_common::baseline::{Baseline, DeviceEntry};
use lusby_common::types::DeviceInfo;
use std::io::{self, Stdout};
use tui::layout::{Constraint, Direction, Layout};
use tui::widgets::{Block, Borders, List, ListItem, Paragraph};
use tui::{backend::CrosstermBackend, Terminal};

/// Serial equality treating missing and empty as the same device.
/// (Entries normalize empty serials to None on insert; without this the
/// "[selected]" marker never shows for serial-less devices and Enter
/// keeps pushing duplicates.)
fn serial_matches(entry_serial: Option<&str>, device_serial: &str) -> bool {
    entry_serial.unwrap_or("") == device_serial
}

fn entry_matches(entry: &DeviceEntry, d: &DeviceInfo) -> bool {
    entry.vendor_id == d.vendor_id
        && entry.product_id == d.product_id
        && serial_matches(entry.serial.as_deref(), &d.serial)
}

/// Ensures raw mode is always disabled when the editor exits, including
/// early returns and error paths (otherwise the terminal is left broken).
struct RawModeGuard;
impl RawModeGuard {
    fn enable() -> io::Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

pub fn run_baseline_editor(devices: Vec<DeviceInfo>) -> io::Result<Option<Baseline>> {
    let _raw = RawModeGuard::enable()?;
    let mut stdout: Stdout = io::stdout();
    let backend: CrosstermBackend<&mut Stdout> = CrosstermBackend::new(&mut stdout);
    let mut terminal: Terminal<CrosstermBackend<&mut Stdout>> = Terminal::new(backend)?;

    let mut selected: usize = 0;
    let mut baseline_devices: Vec<DeviceEntry> = Vec::new();
    let mut comment: String = String::new();

    let mut list_state = tui::widgets::ListState::default();
    list_state.select(Some(selected));
    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(2)
                .constraints(
                    [
                        Constraint::Length(3),
                        Constraint::Min(5),
                        Constraint::Length(3),
                    ]
                    .as_ref(),
                )
                .split(f.size());

            let title = Paragraph::new("Lusby Baseline Editor (TUI)")
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(title, chunks[0]);

            let items: Vec<ListItem> = if devices.is_empty() {
                vec![ListItem::new("No devices detected")]
            } else {
                devices
                    .iter()
                    .enumerate()
                    .map(|(i, d)| {
                        let mut line = format!(
                            "{}: {} {} {} {}",
                            i + 1,
                            d.vendor_id,
                            d.product_id,
                            d.serial,
                            d.device_type
                        );
                        if baseline_devices.iter().any(|bd| entry_matches(bd, d)) {
                            line.push_str(" [selected]");
                        }
                        ListItem::new(line)
                    })
                    .collect()
            };
            let list = List::new(items)
                .block(
                    Block::default()
                        .title("Detected Devices (Up/Down, Enter to add/remove)")
                        .borders(Borders::ALL),
                )
                .highlight_symbol("> ");
            f.render_stateful_widget(list, chunks[1], &mut list_state);

            let comment_block = Paragraph::new(format!("Comment: {}", comment))
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(comment_block, chunks[2]);
        })?;

        if event::poll(std::time::Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => {
                        return Ok(None);
                    }
                    KeyCode::Down => {
                        if selected < devices.len().saturating_sub(1) {
                            selected += 1;
                        }
                        list_state.select(Some(selected));
                    }
                    KeyCode::Up => {
                        if selected > 0 {
                            selected = selected.saturating_sub(1);
                        }
                        list_state.select(Some(selected));
                    }
                    KeyCode::Enter => {
                        let Some(d) = devices.get(selected) else {
                            continue;
                        };
                        if let Some(idx) =
                            baseline_devices.iter().position(|bd| entry_matches(bd, d))
                        {
                            baseline_devices.remove(idx);
                        } else {
                            baseline_devices.push(DeviceEntry {
                                vendor_id: d.vendor_id.clone(),
                                product_id: d.product_id.clone(),
                                serial: if d.serial.is_empty() {
                                    None
                                } else {
                                    Some(d.serial.clone())
                                },
                                bus_path: None,
                                descriptors_hash: String::new(),
                                device_type: d.device_type.clone(),
                                comment: None,
                            });
                        }
                    }
                    KeyCode::Char('c') => {
                        // For simplicity, just prompt in terminal
                        disable_raw_mode()?;
                        println!("Enter comment: ");
                        let mut input = String::new();
                        let read = io::stdin().read_line(&mut input);
                        // Always restore raw mode, even if reading failed.
                        let _ = enable_raw_mode();
                        read?;
                        comment = input.trim().to_string();
                    }
                    KeyCode::Char('s') => {
                        let devices_with_comment: Vec<DeviceEntry> = baseline_devices
                            .iter()
                            .cloned()
                            .map(|mut d| {
                                d.comment = if comment.is_empty() {
                                    None
                                } else {
                                    Some(comment.clone())
                                };
                                d
                            })
                            .collect();
                        let baseline: Baseline = Baseline {
                            version: 1,
                            created_by: whoami::username(),
                            created_at: chrono::Utc::now(),
                            devices: devices_with_comment,
                            signature: None,
                        };
                        return Ok(Some(baseline));
                    }
                    _ => {}
                }
            }
        }
    }
}
