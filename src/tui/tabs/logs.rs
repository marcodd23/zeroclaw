//! Logs tab -- scrollable log viewer.

use crate::tui::theme;
use ratatui::{prelude::*, widgets::*};

pub fn render(frame: &mut Frame, area: Rect) {
    let items: Vec<ListItem> = vec![ListItem::new(Line::from(vec![
        Span::styled("[INFO] ", Style::default().fg(theme::SUCCESS)),
        Span::raw("TUI started. Waiting for log stream..."),
    ]))];

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER))
                .title(" Logs (SSE) "),
        )
        .style(Style::default().fg(theme::FG));

    frame.render_widget(list, area);
}
