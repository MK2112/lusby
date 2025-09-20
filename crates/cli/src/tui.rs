use tui::{backend::CrosstermBackend, Terminal};
use tui::widgets::{Block, Borders, List, ListItem, Paragraph};
use tui::layout::{Layout, Constraint, Direction};
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{enable_raw_mode, disable_raw_mode};
use std::io::{self, Stdout};
use guardianusb_common::types::DeviceInfo;
use guardianusb_common::baseline::{Baseline, DeviceEntry};

pub fn run_baseline_editor(devices: Vec<DeviceInfo>) -> io::Result<Option<Baseline>> {
    enable_raw_mode()?;
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
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(5),
                    Constraint::Length(3),
                ].as_ref())
                .split(f.size());

            let title = Paragraph::new("GuardianUSB Baseline Editor (TUI)").block(Block::default().borders(Borders::ALL));
            f.render_widget(title, chunks[0]);

            let items: Vec<ListItem> = devices.iter().enumerate().map(|(i, d)| {
                let mut line = format!("{}: {} {} {} {}", i+1, d.vendor_id, d.product_id, d.serial, d.device_type);
                if baseline_devices.iter().any(|bd| bd.vendor_id == d.vendor_id && bd.product_id == d.product_id && bd.serial.as_deref() == Some(&d.serial)) {
                    line.push_str(" [selected]");
                }
                ListItem::new(line)
            }).collect();
            let list = List::new(items)
                .block(Block::default().title("Detected Devices (Up/Down, Enter to add/remove)").borders(Borders::ALL))
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
                        disable_raw_mode()?;
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
                        let d = &devices[selected];
                        if let Some(idx) = baseline_devices.iter().position(|bd| {
                            bd.vendor_id == d.vendor_id
                                && bd.product_id == d.product_id
                                && bd.serial.as_deref() == Some(&d.serial)
                        }) {
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
                        io::stdin().read_line(&mut input)?;
                        comment = input.trim().to_string();
                        enable_raw_mode()?;
                    }
                    KeyCode::Char('s') => {
                        disable_raw_mode()?;
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