//! DNS protocol primitives. Transport and policy are separate from wire parsing.
pub mod cache;
mod cache_engine;
pub mod cache_reply;
pub mod daemon;
pub mod doctor;
pub mod edns_policy;
pub mod files;
#[cfg(target_os = "linux")]
pub mod filewatch;
pub mod forward;
pub mod forward_service;
pub mod interface_records;
pub mod hostsdir;
pub mod lease_names;
pub mod local;
pub mod loop_detect;
pub mod process;
mod query_policy;
pub mod reply;
pub mod routing;
pub mod service;
pub mod tcp_service;
pub mod tcp_upstream;
pub mod udp_query;
pub mod upstream;
pub mod wire;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod interface_collect;

// Independent excluded diagnostic source, never a release feature.
pub mod udp_stage_diagnostic;
