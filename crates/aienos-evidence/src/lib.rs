//! Host-side evidence tooling for the M0 reference freeze.
//!
//! Replaces the former Python capture and verification scripts. Everything
//! here reads the Linux reference machine directly (procfs, sysfs, git, and a
//! local inference endpoint) and hashes with the kernel's own SHA-256, so the
//! evidence path has no interpreter and no vendor userspace tools.

pub mod canon;
pub mod capture;
pub mod http;
pub mod pe;
pub mod rollback;
pub mod time;
pub mod verify;

/// Evidence schema written by `capture` and accepted by `verify`.
pub const SCHEMA_VERSION: &str = "3.0.0";
