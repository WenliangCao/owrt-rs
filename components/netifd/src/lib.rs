//! Existing network projections and kernel adapters used by diagnostic probes.
//! The daemon retains its own entry point and complete binary test suite.
#![forbid(unsafe_code)]

pub mod clock;
pub mod config;
pub mod device;
pub mod ethtool;
pub mod ethtool_modes;
pub mod interface;
pub mod ip;
pub mod logging;
pub mod netdev_types;
pub mod netlink;
pub mod rt;
pub mod sys;
pub mod ubus;
pub mod wireless;
