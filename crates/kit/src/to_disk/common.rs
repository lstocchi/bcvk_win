//! Common types and utilities shared across all platforms

use crate::install_options::InstallOptions;
use crate::run_ephemeral::CommonVmOpts;
use camino::Utf8PathBuf;
use clap::{Parser, ValueEnum};
use color_eyre::Result;
use tracing::debug;

/// Supported disk image formats
#[derive(Debug, Clone, ValueEnum, PartialEq, Default)]
pub enum Format {
    /// Raw disk image format (default)
    #[default]
    Raw,
    /// QEMU Copy On Write 2 format
    Qcow2,
}

impl Format {
    /// Get the string representation for qemu-img
    pub fn as_str(&self) -> &'static str {
        match self {
            Format::Raw => "raw",
            Format::Qcow2 => "qcow2",
        }
    }
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Additional configuration options for installing a bootc container image to disk
#[derive(Debug, Parser, Default)]
pub struct ToDiskAdditionalOpts {
    /// Disk size to create (e.g. 10G, 5120M, or plain number for bytes)
    #[clap(long)]
    pub disk_size: Option<String>,

    /// Output disk image format
    #[clap(long, default_value_t = Format::Raw)]
    pub format: Format,

    /// Common VM configuration options
    #[clap(flatten)]
    pub common: CommonVmOpts,

    /// Configure logging for `bootc install` by setting the `RUST_LOG` environment variable.
    #[clap(long)]
    pub install_log: Option<String>,

    #[clap(
        long = "label",
        help = "Add metadata to the container in key=value form"
    )]
    pub label: Vec<String>,

    /// Check if the disk would be regenerated without actually creating it
    #[clap(long)]
    pub dry_run: bool,
}

/// Configuration options for installing a bootc container image to disk
///
/// See the module-level documentation for details on the installation architecture and workflow.
#[derive(Debug, Parser)]
pub struct ToDiskOpts {
    /// Container image to install
    pub source_image: String,

    /// Target disk/device path
    pub target_disk: Utf8PathBuf,

    /// Installation options (filesystem, root-size, storage-path)
    #[clap(flatten)]
    pub install: InstallOptions,

    /// Additional installation options
    #[clap(flatten)]
    pub additional: ToDiskAdditionalOpts,
}

impl ToDiskOpts {
    /// Calculate the optimal target disk size based on the source image or explicit size
    ///
    /// Returns explicit disk_size if provided (parsed from human-readable format),
    /// otherwise 2x the image size with a 4GB minimum.
    pub fn calculate_disk_size(&self) -> Result<u64> {
        if let Some(ref size_str) = self.additional.disk_size {
            let parsed = crate::utils::parse_size(size_str)?;
            debug!("Using explicit disk size: {} -> {} bytes", size_str, parsed);
            return Ok(parsed);
        }

        // Get the image size and multiply by 2 for installation space
        let image_size = crate::images::get_image_size(&self.source_image)?;
        debug!("Image size for {}: {} bytes", self.source_image, image_size);

        // Minimum 4GB, otherwise 2x the image size
        let min_4gb = 4u64 * 1024 * 1024 * 1024;
        let disk_size = std::cmp::max(image_size * 2, min_4gb);
        debug!(
            "Calculated disk size: {} bytes (max({} * 2 = {}, {} min))",
            disk_size,
            image_size,
            image_size * 2,
            min_4gb
        );
        Ok(disk_size)
    }
}
