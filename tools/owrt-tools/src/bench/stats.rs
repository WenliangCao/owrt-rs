//! Python-compatible numbers and summary statistics for benchmark evidence.
//!
//! The published summaries keep Python's int/float distinction: `statistics`
//! returns an int median for an odd count of ints, an int mean when an int
//! mean is exact, and the original element for min/max.

use std::cmp::Ordering;

use serde_json::{json, Value};

use crate::util::{bail, ensure, Result};

/// A JSON number with Python's int/float distinction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Num {
    Int(i64),
    Float(f64),
}

impl Num {
    pub fn f(self) -> f64 {
        match self {
            Num::Int(value) => value as f64,
            Num::Float(value) => value,
        }
    }

    /// Python `a + b`: int when both are ints.
    pub fn add(self, other: Num) -> Num {
        match (self, other) {
            (Num::Int(a), Num::Int(b)) => a
                .checked_add(b)
                .map_or(Num::Float(a as f64 + b as f64), Num::Int),
            _ => Num::Float(self.f() + other.f()),
        }
    }

    /// Python `a - b`: int when both are ints.
    pub fn sub(self, other: Num) -> Num {
        match (self, other) {
            (Num::Int(a), Num::Int(b)) => a
                .checked_sub(b)
                .map_or(Num::Float(a as f64 - b as f64), Num::Int),
            _ => Num::Float(self.f() - other.f()),
        }
    }

    pub fn value(self) -> Value {
        match self {
            Num::Int(value) => json!(value),
            Num::Float(value) => json!(value),
        }
    }
}

/// A JSON number (bools are not numbers here).
pub fn num(value: &Value) -> Result<Num> {
    if let Some(int) = value.as_i64() {
        return Ok(Num::Int(int));
    }
    if let Some(float) = value.as_f64() {
        return Ok(Num::Float(float));
    }
    bail!("expected a number, found {value}")
}

pub fn f(value: &Value) -> Result<f64> {
    Ok(num(value)?.f())
}

/// Python `sum(...)` of numbers: int 0 when empty, int when all are ints.
pub fn sum_nums(values: impl IntoIterator<Item = Num>) -> Num {
    values.into_iter().fold(Num::Int(0), Num::add)
}

/// Python `math.isclose`.
pub fn isclose(a: f64, b: f64, rel: f64, abs: f64) -> bool {
    a == b || (a - b).abs() <= (rel * a.abs().max(b.abs())).max(abs)
}

/// Python equality of decoded JSON: numbers compare by value across int and
/// float; objects compare without regard to key order.
pub fn py_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_i64(), y.as_i64()) {
            (Some(x), Some(y)) => x == y,
            _ => x.as_f64() == y.as_f64(),
        },
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| py_eq(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| py_eq(v, w)))
        }
        _ => a == b,
    }
}

/// A double-double value (`hi + lo`, about 106 bits). Python's `statistics`
/// sums exactly with fractions and rounds once; double-double reproduces that
/// single rounding for every realistic input.
#[derive(Clone, Copy)]
struct Dd(f64, f64);

fn two_sum(a: f64, b: f64) -> (f64, f64) {
    let sum = a + b;
    let b_virtual = sum - a;
    (sum, (a - (sum - b_virtual)) + (b - b_virtual))
}

fn normalize(hi: f64, lo: f64) -> Dd {
    let sum = hi + lo;
    Dd(sum, lo - (sum - hi))
}

impl Dd {
    fn add(self, other: Dd) -> Dd {
        let (sum, error) = two_sum(self.0, other.0);
        normalize(sum, error + self.1 + other.1)
    }

    fn neg(self) -> Dd {
        Dd(-self.0, -self.1)
    }

    fn mul(self, other: Dd) -> Dd {
        let product = self.0 * other.0;
        let error = self.0.mul_add(other.0, -product) + (self.0 * other.1 + self.1 * other.0);
        normalize(product, error)
    }

    fn div(self, divisor: f64) -> Dd {
        let first = self.0 / divisor;
        let product = first * divisor;
        let product_error = first.mul_add(divisor, -product);
        let (rest, error) = two_sum(self.0, -product);
        normalize(first, (rest + (error - product_error + self.1)) / divisor)
    }

    /// Square root rounded once, after one Newton step in double-double.
    fn sqrt(self) -> f64 {
        if self.0 <= 0.0 {
            return 0.0;
        }
        let root = self.0.sqrt();
        let square = root * root;
        let residual = (self.0 - square) - root.mul_add(root, -square) + self.1;
        root + residual / (2.0 * root)
    }
}

fn exact_mean(values: &[Num]) -> Dd {
    let total = values
        .iter()
        .fold(Dd(0.0, 0.0), |total, value| total.add(Dd(value.f(), 0.0)));
    total.div(values.len() as f64)
}

/// Python `statistics.mean`.
pub fn mean(values: &[Num]) -> Result<Num> {
    ensure!(!values.is_empty(), "mean requires at least one data point");
    if let Some(ints) = values
        .iter()
        .map(|v| {
            if let Num::Int(i) = v {
                Some(i128::from(*i))
            } else {
                None
            }
        })
        .collect::<Option<Vec<_>>>()
    {
        let total: i128 = ints.iter().sum();
        let count = ints.len() as i128;
        return Ok(if total % count == 0 {
            Num::Int((total / count) as i64)
        } else {
            Num::Float(total as f64 / count as f64)
        });
    }
    Ok(Num::Float(exact_mean(values).0))
}

fn sorted(values: &[Num]) -> Vec<Num> {
    let mut data = values.to_vec();
    data.sort_by(|a, b| a.f().partial_cmp(&b.f()).unwrap_or(Ordering::Equal));
    data
}

/// Python `statistics.median`.
pub fn median(values: &[Num]) -> Result<Num> {
    ensure!(!values.is_empty(), "no median for empty data");
    let data = sorted(values);
    let n = data.len();
    Ok(if n % 2 == 1 {
        data[n / 2]
    } else {
        Num::Float((data[n / 2 - 1].f() + data[n / 2].f()) / 2.0)
    })
}

/// Python `statistics.stdev` (sample standard deviation).
pub fn stdev(values: &[Num]) -> Result<f64> {
    ensure!(values.len() > 1, "stdev requires at least two data points");
    let centre = exact_mean(values).neg();
    let squares = values.iter().fold(Dd(0.0, 0.0), |total, value| {
        let deviation = Dd(value.f(), 0.0).add(centre);
        total.add(deviation.mul(deviation))
    });
    Ok(squares.div((values.len() - 1) as f64).sqrt())
}

/// Python `min()`/`max()`: the first extreme element.
fn extreme(values: &[Num], want: Ordering) -> Num {
    let mut best = values[0];
    for &value in &values[1..] {
        if value.f().partial_cmp(&best.f()) == Some(want) {
            best = value;
        }
    }
    best
}

/// `{"n", "median", "mean", "min", "max", "stdev"}` of finite values.
pub fn stats(values: &[Num]) -> Result<Value> {
    ensure!(
        !values.is_empty() && values.iter().all(|v| v.f().is_finite()),
        "statistics require finite values"
    );
    let stdev = if values.len() > 1 {
        json!(stdev(values)?)
    } else {
        json!(0)
    };
    Ok(
        json!({"n": values.len(), "median": median(values)?.value(), "mean": mean(values)?.value(),
              "min": extreme(values, Ordering::Less).value(), "max": extreme(values, Ordering::Greater).value(),
              "stdev": stdev}),
    )
}

/// Statistics of JSON numbers.
pub fn value_stats<'a>(values: impl IntoIterator<Item = &'a Value>) -> Result<Value> {
    let values: Vec<Num> = values.into_iter().map(num).collect::<Result<_>>()?;
    stats(&values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_statistics_types_and_values() {
        let ints = [Num::Int(1), Num::Int(3), Num::Int(20)];
        assert_eq!(
            stats(&ints).unwrap(),
            json!({"n": 3, "median": 3, "mean": 8, "min": 1, "max": 20, "stdev": stdev(&ints).unwrap()})
        );
        assert_eq!(
            median(&[Num::Int(1), Num::Int(3)]).unwrap(),
            Num::Float(2.0)
        );
        assert_eq!(mean(&[Num::Int(1), Num::Int(2)]).unwrap(), Num::Float(1.5));
        assert_eq!(stats(&[Num::Float(0.5)]).unwrap()["stdev"], json!(0));
        assert!(
            (stdev(&[
                Num::Int(2),
                Num::Int(4),
                Num::Int(4),
                Num::Int(4),
                Num::Int(5),
                Num::Int(5),
                Num::Int(7),
                Num::Int(9)
            ])
            .unwrap()
                - 2.138089935299395)
                .abs()
                < 1e-12
        );
        assert!(stats(&[Num::Float(f64::INFINITY)]).is_err());
        // Python 3.14 `statistics`: exact sums, one rounding.
        let floats = |values: &[f64]| values.iter().map(|&v| Num::Float(v)).collect::<Vec<_>>();
        assert_eq!(
            stdev(&floats(&[0.1, 0.2, 0.3, 0.7])).unwrap(),
            0.26299556396765833
        );
        assert_eq!(
            mean(&floats(&[0.1, 0.2, 0.3, 0.7])).unwrap(),
            Num::Float(0.325)
        );
        assert_eq!(
            stdev(&floats(&[1e16, 1.0, -1e16, 3.5])).unwrap(),
            8164965809277260.0
        );
        assert_eq!(
            stdev(&floats(&[706.5, 719.5, 732.5, 745.5, 758.5, 771.5])).unwrap(),
            24.320773014030618
        );
        assert_eq!(mean(&floats(&[1.1, 2.2, 3.3])).unwrap(), Num::Float(2.2));
        assert_eq!(
            stdev(&floats(&[1.1, 2.2, 3.3, 4.4, 5.5])).unwrap(),
            1.7392527130926085
        );
        assert!(py_eq(
            &json!({"a": 1, "b": [2.0]}),
            &json!({"b": [2], "a": 1.0})
        ));
    }
}
