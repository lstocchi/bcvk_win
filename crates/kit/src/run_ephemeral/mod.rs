mod common;

#[cfg(target_os = "linux")]
mod linux;

pub use common::CommonVmOpts;
