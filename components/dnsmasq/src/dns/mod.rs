//! DNS protocol primitives. Transport and policy are separate from wire parsing.
pub mod cache;
pub mod cache_reply;
pub mod daemon;
pub mod forward;
pub mod forward_service;
pub mod local;
pub mod process;
pub mod reply;
pub mod routing;
pub mod service;
pub mod tcp_service;
pub mod tcp_upstream;
pub mod upstream;
pub mod wire;
