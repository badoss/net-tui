//! Single-line text editor backing the filter prompts.

/// Cursor-aware line buffer. The cursor is a byte offset that is always kept on
/// a `char` boundary, so multi-byte input survives editing.
#[derive(Default, Clone)]
pub struct LineInput {
    value: String,
    cursor: usize,
}

impl LineInput {
    pub fn with_value(value: impl Into<String>) -> Self {
        let value = value.into();
        let cursor = value.len();
        Self { value, cursor }
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    /// Cursor position measured in characters, for placing the terminal caret.
    pub fn cursor_chars(&self) -> usize {
        self.value[..self.cursor].chars().count()
    }

    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }

    pub fn insert(&mut self, ch: char) {
        self.value.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
    }

    pub fn backspace(&mut self) {
        if let Some(prev) = self.prev_boundary() {
            self.value.remove(prev);
            // `remove` takes a byte index and shifts the tail down; recompute
            // rather than subtracting a fixed width.
            self.cursor = prev;
        }
    }

    pub fn delete(&mut self) {
        if self.cursor < self.value.len() {
            self.value.remove(self.cursor);
        }
    }

    pub fn left(&mut self) {
        if let Some(prev) = self.prev_boundary() {
            self.cursor = prev;
        }
    }

    pub fn right(&mut self) {
        if let Some(next) = self.next_boundary() {
            self.cursor = next;
        }
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.value.len();
    }

    /// Deletes the whitespace-delimited word before the cursor (Ctrl+W).
    pub fn delete_word(&mut self) {
        let head = &self.value[..self.cursor];
        let trimmed = head.trim_end();
        let start = trimmed.rfind(char::is_whitespace).map_or(0, |i| {
            i + trimmed[i..].chars().next().map_or(1, char::len_utf8)
        });
        self.value.replace_range(start..self.cursor, "");
        self.cursor = start;
    }

    /// Deletes everything before the cursor (Ctrl+U).
    pub fn delete_to_start(&mut self) {
        self.value.replace_range(..self.cursor, "");
        self.cursor = 0;
    }

    fn prev_boundary(&self) -> Option<usize> {
        self.value[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(i, _)| i)
    }

    fn next_boundary(&self) -> Option<usize> {
        self.value[self.cursor..]
            .chars()
            .next()
            .map(|c| self.cursor + c.len_utf8())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_stay_on_char_boundaries_for_multibyte_input() {
        let mut input = LineInput::default();
        for ch in "ทดสอบ".chars() {
            input.insert(ch);
        }
        assert_eq!(input.cursor_chars(), 5);
        input.backspace();
        assert_eq!(input.value(), "ทดสอ");
        // The cursor sits after "ส", so the insert lands before the last char.
        input.left();
        input.insert('x');
        assert_eq!(input.value(), "ทดสxอ");
        assert_eq!(input.cursor_chars(), 4);
    }

    #[test]
    fn delete_word_removes_the_token_before_the_cursor() {
        let mut input = LineInput::with_value("tcp port 443");
        input.delete_word();
        assert_eq!(input.value(), "tcp port ");
        input.delete_word();
        assert_eq!(input.value(), "tcp ");
    }

    #[test]
    fn delete_word_on_a_single_token_empties_the_line() {
        let mut input = LineInput::with_value("udp");
        input.delete_word();
        assert_eq!(input.value(), "");
        assert_eq!(input.cursor_chars(), 0);
    }

    #[test]
    fn delete_to_start_keeps_the_tail_after_the_cursor() {
        let mut input = LineInput::with_value("tcp port 443");
        input.home();
        input.right();
        input.right();
        input.right();
        input.delete_to_start();
        assert_eq!(input.value(), " port 443");
        assert_eq!(input.cursor_chars(), 0);
    }
}
