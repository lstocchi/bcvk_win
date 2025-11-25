mod common;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(not(target_os = "linux"))]
mod fallback;

pub use common::{generate_unique_vm_name, parse_memory_to_mb, parse_size};

#[cfg(target_os = "linux")]
pub use linux::{
    detect_container_storage_path, parse_size, validate_container_storage_path, wait_for_readiness,
};

#[cfg(not(target_os = "linux"))]
pub use fallback::CommandRunExt;
