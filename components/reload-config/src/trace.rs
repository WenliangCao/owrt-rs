//! JSONL diagnostics for configuration comparison, delivery and fatal errors.

use std::io::{self, Write};

pub struct Trace<W: Write> {
    writer: W,
}

impl<W: Write> Trace<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn comparison(
        &mut self,
        compared_count: usize,
        changed: &[String],
        new_baseline_count: usize,
    ) -> io::Result<()> {
        write!(
            self.writer,
            "{{\"schema\":1,\"kind\":\"comparison\",\"compared_count\":{compared_count},\"changed_entries\":["
        )?;
        write_strings(&mut self.writer, changed)?;
        writeln!(
            self.writer,
            "],\"new_baseline_count\":{new_baseline_count}}}"
        )
    }

    pub fn normalization(&mut self, package: &str, status: &str) -> io::Result<()> {
        writeln!(
            self.writer,
            "{{\"schema\":1,\"kind\":\"normalization\",\"package\":\"{}\",\"status\":\"{}\"}}",
            escape(package),
            escape(status)
        )
    }

    pub fn delivery(
        &mut self,
        package: &str,
        outcome: &str,
        status: Option<i32>,
    ) -> io::Result<()> {
        write!(
            self.writer,
            "{{\"schema\":1,\"kind\":\"delivery\",\"package\":\"{}\",\"outcome\":\"{}\",\"status\":",
            escape(package),
            escape(outcome)
        )?;
        match status {
            Some(value) => write!(self.writer, "{value}")?,
            None => write!(self.writer, "null")?,
        }
        writeln!(self.writer, "}}")
    }

    pub fn complete(
        &mut self,
        baseline_rewritten: bool,
        delivery_failures: usize,
    ) -> io::Result<()> {
        writeln!(
            self.writer,
            "{{\"schema\":1,\"kind\":\"complete\",\"baseline_rewritten\":{baseline_rewritten},\"delivery_failures\":{delivery_failures}}}"
        )
    }

    pub fn fatal(&mut self, class: &str, message: &str) -> io::Result<()> {
        writeln!(
            self.writer,
            "{{\"schema\":1,\"kind\":\"fatal\",\"class\":\"{}\",\"message\":\"{}\"}}",
            escape(class),
            escape(message)
        )
    }
}

fn write_strings(writer: &mut impl Write, values: &[String]) -> io::Result<()> {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            write!(writer, ",")?;
        }
        write!(writer, "\"{}\"", escape(value))?;
    }
    Ok(())
}

pub fn escape(value: &str) -> String {
    // Escaping only replaces ASCII bytes with ASCII sequences; UTF-8 input
    // therefore remains UTF-8 without a second, drifting implementation.
    String::from_utf8(crate::json::escape_bytes(value.as_bytes())).expect("escaped UTF-8")
}

#[cfg(test)]
mod tests {
    use super::escape;

    #[test]
    fn json_escape_covers_control_characters() {
        assert_eq!(escape("a\"b\\c\n\t\u{1}"), "a\\\"b\\\\c\\n\\t\\u0001");
    }
}
