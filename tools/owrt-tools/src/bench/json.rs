//! Strict accessors over decoded evidence: a missing field, a wrong type or a
//! missing process is an error, never a silent default.

use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use super::stats::{self, num, py_eq, Num};
use crate::util::{self, bail, Error, Result};

pub fn key<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| Error::new(format!("missing field {name:?}")))
}

/// Nested field lookup.
pub fn at<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Value> {
    path.iter().try_fold(value, |value, name| key(value, name))
}

pub fn kf(value: &Value, name: &str) -> Result<f64> {
    stats::f(key(value, name)?)
}

pub fn kn(value: &Value, name: &str) -> Result<Num> {
    num(key(value, name)?)
}

pub fn ki(value: &Value, name: &str) -> Result<i64> {
    key(value, name)?
        .as_i64()
        .ok_or_else(|| Error::new(format!("{name} is not an integer")))
}

pub fn ks<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    key(value, name)?
        .as_str()
        .ok_or_else(|| Error::new(format!("{name} is not a string")))
}

pub fn list<'a>(value: &'a Value, name: &str) -> Result<&'a Vec<Value>> {
    key(value, name)?
        .as_array()
        .ok_or_else(|| Error::new(format!("{name} is not a list")))
}

pub fn obj<'a>(value: &'a Value, name: &str) -> Result<&'a Map<String, Value>> {
    key(value, name)?
        .as_object()
        .ok_or_else(|| Error::new(format!("{name} is not an object")))
}

/// Python truthiness of an optional field.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64() != Some(0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(fields)) => !fields.is_empty(),
    }
}

/// Field equality with a string, as Python `value == "text"`.
pub fn is(value: Option<&Value>, text: &str) -> bool {
    value.and_then(Value::as_str) == Some(text)
}

pub fn strings(values: &[Value]) -> Result<Vec<String>> {
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::new("expected a string"))
        })
        .collect()
}

/// Copies `names` in order.
pub fn pick(value: &Value, names: &[&str]) -> Result<Map<String, Value>> {
    names
        .iter()
        .map(|name| Ok(((*name).to_owned(), key(value, name)?.clone())))
        .collect()
}

pub fn merge(target: &mut Map<String, Value>, source: Map<String, Value>) {
    for (name, value) in source {
        target.insert(name, value);
    }
}

pub fn read(path: &Path) -> Result<Value> {
    util::read_json(path)
}

pub fn bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|error| Error::new(format!("{}: {error}", util::display(path))))
}

pub fn text(path: &Path) -> Result<String> {
    util::read_text(path)
}

/// `path.read_text().split()[0]`.
pub fn first_word(path: &Path) -> Result<String> {
    let text = text(path)?;
    match text.split_whitespace().next() {
        Some(word) => Ok(word.to_owned()),
        None => bail!("{} is empty", util::display(path)),
    }
}

/// `[line.split()[0] for line in path.read_text().splitlines()]`.
pub fn first_words(path: &Path) -> Result<Vec<String>> {
    let text = text(path)?;
    util::splitlines(&text)
        .into_iter()
        .map(|line| match line.split_whitespace().next() {
            Some(word) => Ok(word.to_owned()),
            None => bail!("{}: empty line", util::display(path)),
        })
        .collect()
}

pub fn lines(path: &Path) -> Result<Vec<String>> {
    Ok(util::splitlines(&text(path)?)
        .into_iter()
        .map(str::to_owned)
        .collect())
}

pub fn json_lines(path: &Path) -> Result<Vec<Value>> {
    let text = text(path)?;
    util::splitlines(&text)
        .into_iter()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

/// Python `next(p for p in processes if p["pid"] == pid)`, or `None`.
pub fn find_pid<'a>(processes: &'a [Value], pid: &Value) -> Result<Option<&'a Value>> {
    for process in processes {
        if py_eq(key(process, "pid")?, pid) {
            return Ok(Some(process));
        }
    }
    Ok(None)
}

pub fn need_pid<'a>(processes: &'a [Value], pid: &Value) -> Result<&'a Value> {
    find_pid(processes, pid)?.ok_or_else(|| Error::new(format!("process {pid} is missing")))
}

/// Hash key of a JSON PID: equal numbers share one key, as in a Python dict.
pub fn pid_key(pid: &Value) -> String {
    match (pid.as_i64(), pid.as_f64()) {
        (Some(int), _) => int.to_string(),
        (None, Some(float)) if float.fract() == 0.0 && float.abs() < 9.0e15 => {
            (float as i64).to_string()
        }
        _ => pid.to_string(),
    }
}

/// `{p["pid"]: p for p in processes}`: first position, last value.
pub struct Procs<'a> {
    entries: Vec<(String, &'a Value, &'a Value)>,
}

impl<'a> Procs<'a> {
    pub fn new(processes: &'a [Value]) -> Result<Self> {
        let mut entries: Vec<(String, &Value, &Value)> = Vec::new();
        for process in processes {
            let pid = key(process, "pid")?;
            let name = pid_key(pid);
            match entries.iter_mut().find(|entry| entry.0 == name) {
                Some(entry) => entry.2 = process,
                None => entries.push((name, pid, process)),
            }
        }
        Ok(Self { entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(&self, pid: &Value) -> Option<&'a Value> {
        let name = pid_key(pid);
        self.entries
            .iter()
            .find(|entry| entry.0 == name)
            .map(|entry| entry.2)
    }

    pub fn need(&self, pid: &Value) -> Result<&'a Value> {
        self.get(pid)
            .ok_or_else(|| Error::new(format!("process {pid} is missing")))
    }

    pub fn contains(&self, pid: &Value) -> bool {
        self.get(pid).is_some()
    }

    /// `(pid, process)` in dict order.
    pub fn iter(&self) -> impl Iterator<Item = (&'a Value, &'a Value)> + '_ {
        self.entries.iter().map(|entry| (entry.1, entry.2))
    }

    pub fn keys(&self) -> std::collections::BTreeSet<String> {
        self.entries.iter().map(|entry| entry.0.clone()).collect()
    }
}

pub fn pid_set<'a>(
    pids: impl IntoIterator<Item = &'a Value>,
) -> std::collections::BTreeSet<String> {
    pids.into_iter().map(pid_key).collect()
}
