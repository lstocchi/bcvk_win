//! Install bootc images to disk using ephemeral VMs
//!
//! This module provides the core installation functionality for bcvk, enabling
//! automated installation of bootc container images to disk images.

mod common;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod fallback;

pub use common::{Format, ToDiskOpts};

#[cfg(target_os = "linux")]
pub use linux::run;

#[cfg(target_os = "windows")]
pub use windows::run;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub use fallback::run;
