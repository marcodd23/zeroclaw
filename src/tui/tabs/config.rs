//! Config tab -- TOML viewer with editor launch.

use crate::tui::theme;
use ratatui::{prelude::*, widgets::*};

pub fn render(frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),    // Config display
            Constraint::Length(3), // Help bar
        ])
        .split(area);

    let config_text = vec![
        Line::from("Configuration will be loaded from the gateway."),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "Tip: ",
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Press 'e' to open config in $EDITOR"),
        ]),
    ];

    let config_widget = Paragraph::new(config_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER))
                .title(" Config (TOML) "),
        )
        .style(Style::default().fg(theme::FG));
    frame.render_widget(config_widget, chunks[0]);

    let help = Paragraph::new(" e: open in $EDITOR | r: refresh")
        .style(Style::default().fg(theme::FG_DIM));
    frame.render_widget(help, chunks[1]);
}
