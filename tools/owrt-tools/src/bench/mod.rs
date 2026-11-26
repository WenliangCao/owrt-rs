//! Benchmark collection and analysis: `run-candidate` drives one component
//! matrix on the router; `analyze` and `analyze-candidate` derive the
//! publishable summaries from the private evidence.

pub mod analyze;
pub mod candidate;
mod json;
mod mt;
pub mod run_candidate;
mod stats;
