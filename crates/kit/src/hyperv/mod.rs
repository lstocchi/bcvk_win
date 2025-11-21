//! hyperv integration for bcvk
//!
//! This module provides a comprehensive hyperv integration with subcommands for:
//! - `run`: Run a bootable container as a persistent VM
//! - `list`: List bootc domains with metadata
//! - `upload`: Upload bootc disk images to hyperv with metadata annotations
//! - `list-volumes`: List available bootc volumes with metadata

use clap::Subcommand;

pub mod run;

/// hyperv subcommands for managing bootc disk images and domains
#[derive(Debug, Subcommand)]
pub enum HypervSubcommands {
    /// Run a bootable container as a persistent VM
    Run(run::HypervRunOpts),
}