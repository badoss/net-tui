//! Interactive editor for a [`FilterSpec`].
//!
//! Holds only its own state; anything needing the packet ring or the capture
//! handle is returned to [`crate::app::App`] as an [`Action`].

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;

use crate::filter::{FilterSpec, FilterTarget};
use crate::input::LineInput;
use crate::packet::{ALL_PROTOS, Proto};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Field {
    Source,
    Destination,
    Protocol,
    Port,
    PortSide,
    Target,
}

pub const FIELDS: [Field; 6] = [
    Field::Source,
    Field::Destination,
    Field::Protocol,
    Field::Port,
    Field::PortSide,
    Field::Target,
];

impl Field {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Source => "Source",
            Self::Destination => "Destination",
            Self::Protocol => "Protocol",
            Self::Port => "Port",
            Self::PortSide => "Port side",
            Self::Target => "Apply to",
        }
    }

    /// Text fields are typed into and can be filled from observed traffic;
    /// the rest cycle through a fixed set with ← / →.
    pub const fn is_text(self) -> bool {
        matches!(self, Self::Source | Self::Destination | Self::Port)
    }

    pub const fn hint(self) -> &'static str {
        match self {
            Self::Source => "IP address, or part of one",
            Self::Destination => "IP address, or part of one",
            Self::Protocol => "← → to change",
            Self::Port => "0-65535",
            Self::PortSide => "← → to change",
            Self::Target => "← → to change",
        }
    }
}

/// What the builder needs the app to do next.
#[derive(PartialEq, Eq, Debug)]
pub enum Action {
    None,
    Close,
    Apply,
    /// Populate and open the observed-values list for the focused field.
    RequestValues(Field),
}

/// Values actually seen in the capture, most frequent first.
pub struct Picker {
    pub field: Field,
    pub values: Vec<(String, u64)>,
    pub state: ListState,
}

impl Picker {
    pub fn new(field: Field, values: Vec<(String, u64)>) -> Self {
        let mut state = ListState::default();
        state.select((!values.is_empty()).then_some(0));
        Self {
            field,
            values,
            state,
        }
    }

    fn move_by(&mut self, delta: isize) {
        if self.values.is_empty() {
            return;
        }
        let last = self.values.len() as isize - 1;
        let current = self.state.selected().unwrap_or(0) as isize;
        self.state
            .select(Some((current + delta).clamp(0, last) as usize));
    }

    fn selected(&self) -> Option<&str> {
        self.state
            .selected()
            .and_then(|i| self.values.get(i))
            .map(|(value, _)| value.as_str())
    }
}

pub struct Builder {
    pub spec: FilterSpec,
    pub target: FilterTarget,
    pub field: usize,
    /// Edit buffer for the focused text field, written back to `spec` whenever
    /// focus moves or the spec is read.
    pub input: LineInput,
    pub picker: Option<Picker>,
    pub error: Option<String>,
}

impl Builder {
    pub fn new(spec: FilterSpec, target: FilterTarget) -> Self {
        let mut builder = Self {
            spec,
            target,
            field: 0,
            input: LineInput::default(),
            picker: None,
            error: None,
        };
        builder.load_input();
        builder
    }

    pub fn focused(&self) -> Field {
        FIELDS[self.field]
    }

    /// The spec including any uncommitted text in the edit buffer.
    pub fn current_spec(&self) -> FilterSpec {
        let mut spec = self.spec.clone();
        write_field(&mut spec, self.focused(), self.input.value());
        spec
    }

    pub fn value_of(&self, field: Field) -> String {
        if field == self.focused() && field.is_text() {
            return self.input.value().to_string();
        }
        read_field(&self.spec, field, self.target)
    }

    fn load_input(&mut self) {
        let field = self.focused();
        self.input = if field.is_text() {
            LineInput::with_value(read_field(&self.spec, field, self.target))
        } else {
            LineInput::default()
        };
    }

    fn commit_input(&mut self) {
        let field = self.focused();
        if field.is_text() {
            write_field(&mut self.spec, field, self.input.value());
        }
    }

    fn move_field(&mut self, delta: isize) {
        self.commit_input();
        let last = FIELDS.len() as isize - 1;
        self.field = (self.field as isize + delta).clamp(0, last) as usize;
        self.load_input();
    }

    /// Cycles the focused choice field. Returns false for text fields so the
    /// caller can fall back to cursor movement.
    fn cycle(&mut self, forward: bool) -> bool {
        match self.focused() {
            Field::Protocol => {
                self.spec.protocol = cycle_protocol(self.spec.protocol, forward);
                true
            }
            Field::PortSide => {
                self.spec.port_side = if forward {
                    self.spec.port_side.next()
                } else {
                    self.spec.port_side.previous()
                };
                true
            }
            Field::Target => {
                self.target = self.target.toggled();
                true
            }
            _ => false,
        }
    }

    pub fn accept_value(&mut self, value: &str) {
        if let Some(picker) = self.picker.take() {
            write_field(&mut self.spec, picker.field, value);
            if picker.field == self.focused() {
                self.load_input();
            }
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        if self.picker.is_some() {
            return self.on_picker_key(key);
        }

        self.error = None;
        match key.code {
            KeyCode::Esc => Action::Close,
            KeyCode::Enter => Action::Apply,
            KeyCode::Up | KeyCode::BackTab => {
                self.move_field(-1);
                Action::None
            }
            KeyCode::Down | KeyCode::Tab => {
                self.move_field(1);
                Action::None
            }
            KeyCode::Right => {
                if !self.cycle(true) {
                    self.input.right();
                }
                Action::None
            }
            KeyCode::Left => {
                if !self.cycle(false) {
                    self.input.left();
                }
                Action::None
            }
            KeyCode::Char(' ') if !self.focused().is_text() => {
                self.cycle(true);
                Action::None
            }
            // Space is a legal character in no field, but reserving it for
            // cycling everywhere would break nothing and confuse text entry.
            KeyCode::Char('u') if ctrl => {
                self.input.clear();
                self.commit_input();
                Action::None
            }
            KeyCode::Char('w') if ctrl => {
                self.input.delete_word();
                Action::None
            }
            KeyCode::Backspace => {
                self.input.backspace();
                Action::None
            }
            KeyCode::Delete => {
                self.input.delete();
                Action::None
            }
            KeyCode::Home => {
                self.input.home();
                Action::None
            }
            KeyCode::End => {
                self.input.end();
                Action::None
            }
            KeyCode::Char(ch) if ctrl && ch == 'p' => Action::RequestValues(self.focused()),
            KeyCode::Char(ch) if !ctrl && self.focused().is_text() => {
                self.input.insert(ch);
                Action::None
            }
            _ => Action::None,
        }
    }

    fn on_picker_key(&mut self, key: KeyEvent) -> Action {
        let Some(picker) = self.picker.as_mut() else {
            return Action::None;
        };
        match key.code {
            KeyCode::Esc => {
                self.picker = None;
            }
            KeyCode::Enter => {
                let chosen = picker.selected().map(str::to_string);
                match chosen {
                    Some(value) => self.accept_value(&value),
                    None => self.picker = None,
                }
            }
            KeyCode::Up => picker.move_by(-1),
            KeyCode::Down => picker.move_by(1),
            KeyCode::PageUp => picker.move_by(-10),
            KeyCode::PageDown => picker.move_by(10),
            _ => {}
        }
        Action::None
    }
}

fn cycle_protocol(current: Option<Proto>, forward: bool) -> Option<Proto> {
    // The cycle is "any" followed by each protocol, so a full pass returns to
    // an unconstrained field.
    let position = current.map_or(0, |proto| {
        ALL_PROTOS
            .iter()
            .position(|&p| p == proto)
            .map_or(0, |i| i + 1)
    });
    let len = ALL_PROTOS.len() + 1;
    let next = if forward {
        (position + 1) % len
    } else {
        (position + len - 1) % len
    };
    (next > 0).then(|| ALL_PROTOS[next - 1])
}

fn read_field(spec: &FilterSpec, field: Field, target: FilterTarget) -> String {
    match field {
        Field::Source => spec.source.clone(),
        Field::Destination => spec.destination.clone(),
        Field::Port => spec.port.clone(),
        Field::Protocol => spec
            .protocol
            .map_or_else(|| "any".to_string(), |p| p.label().to_string()),
        Field::PortSide => spec.port_side.label().to_string(),
        Field::Target => target.label().to_string(),
    }
}

fn write_field(spec: &mut FilterSpec, field: Field, value: &str) {
    match field {
        Field::Source => spec.source = value.to_string(),
        Field::Destination => spec.destination = value.to_string(),
        Field::Port => spec.port = value.to_string(),
        Field::Protocol | Field::PortSide | Field::Target => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    #[test]
    fn protocol_cycles_through_any_and_back() {
        let mut current = None;
        let mut seen = vec![current];
        for _ in 0..ALL_PROTOS.len() + 1 {
            current = cycle_protocol(current, true);
            seen.push(current);
        }
        assert_eq!(seen.first(), Some(&None));
        assert_eq!(seen.last(), Some(&None), "a full pass returns to any");
        assert_eq!(seen.len(), ALL_PROTOS.len() + 2);
        assert!(ALL_PROTOS.iter().all(|p| seen.contains(&Some(*p))));
    }

    #[test]
    fn protocol_cycles_backwards_symmetrically() {
        assert_eq!(cycle_protocol(None, false), Some(Proto::Other));
        assert_eq!(cycle_protocol(Some(Proto::Tcp), false), None);
    }

    #[test]
    fn typing_lands_in_the_focused_text_field_only() {
        let mut builder = Builder::new(FilterSpec::default(), FilterTarget::Capture);
        assert_eq!(builder.focused(), Field::Source);
        for ch in "10.0.0.1".chars() {
            builder.on_key(key(KeyCode::Char(ch)));
        }
        assert_eq!(builder.current_spec().source, "10.0.0.1");

        // Moving focus commits the buffer and loads the next field.
        builder.on_key(key(KeyCode::Down));
        assert_eq!(builder.focused(), Field::Destination);
        assert_eq!(builder.spec.source, "10.0.0.1");
        for ch in "1.1.1.1".chars() {
            builder.on_key(key(KeyCode::Char(ch)));
        }
        let spec = builder.current_spec();
        assert_eq!(spec.source, "10.0.0.1");
        assert_eq!(spec.destination, "1.1.1.1");
    }

    #[test]
    fn arrows_cycle_choice_fields_but_move_the_cursor_in_text_fields() {
        let mut builder = Builder::new(FilterSpec::default(), FilterTarget::Capture);
        // Source is a text field: → must not change the protocol.
        builder.on_key(key(KeyCode::Right));
        assert_eq!(builder.spec.protocol, None);

        while builder.focused() != Field::Protocol {
            builder.on_key(key(KeyCode::Down));
        }
        builder.on_key(key(KeyCode::Right));
        assert_eq!(builder.spec.protocol, Some(Proto::Tcp));
        builder.on_key(key(KeyCode::Left));
        assert_eq!(builder.spec.protocol, None);
    }

    #[test]
    fn target_toggles_between_capture_and_display() {
        let mut builder = Builder::new(FilterSpec::default(), FilterTarget::Capture);
        while builder.focused() != Field::Target {
            builder.on_key(key(KeyCode::Down));
        }
        builder.on_key(key(KeyCode::Right));
        assert_eq!(builder.target, FilterTarget::Display);
        builder.on_key(key(KeyCode::Char(' ')));
        assert_eq!(builder.target, FilterTarget::Capture);
    }

    #[test]
    fn enter_applies_and_escape_closes() {
        let mut builder = Builder::new(FilterSpec::default(), FilterTarget::Capture);
        assert_eq!(builder.on_key(key(KeyCode::Enter)), Action::Apply);
        assert_eq!(builder.on_key(key(KeyCode::Esc)), Action::Close);
    }

    #[test]
    fn the_picker_writes_the_chosen_value_into_its_own_field() {
        let mut builder = Builder::new(FilterSpec::default(), FilterTarget::Capture);
        assert_eq!(
            builder.on_key(ctrl(KeyCode::Char('p'))),
            Action::RequestValues(Field::Source)
        );

        builder.picker = Some(Picker::new(
            Field::Source,
            vec![("10.0.0.1".to_string(), 42), ("10.0.0.2".to_string(), 7)],
        ));
        builder.on_key(key(KeyCode::Down));
        builder.on_key(key(KeyCode::Enter));

        assert!(builder.picker.is_none());
        assert_eq!(builder.spec.source, "10.0.0.2");
        // The edit buffer must follow, or the next keystroke would revert it.
        assert_eq!(builder.input.value(), "10.0.0.2");
    }

    #[test]
    fn escaping_the_picker_leaves_the_builder_open() {
        let mut builder = Builder::new(FilterSpec::default(), FilterTarget::Capture);
        builder.picker = Some(Picker::new(Field::Source, vec![("1.1.1.1".into(), 1)]));
        assert_eq!(builder.on_key(key(KeyCode::Esc)), Action::None);
        assert!(builder.picker.is_none());
        assert_eq!(builder.spec.source, "");
    }

    #[test]
    fn a_picker_with_no_observed_values_closes_without_writing() {
        let mut builder = Builder::new(FilterSpec::default(), FilterTarget::Capture);
        builder.picker = Some(Picker::new(Field::Source, Vec::new()));
        builder.on_key(key(KeyCode::Enter));
        assert!(builder.picker.is_none());
        assert_eq!(builder.spec.source, "");
    }
}
