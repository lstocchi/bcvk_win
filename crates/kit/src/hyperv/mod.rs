//! hyperv integration for bcvk
//!
//! This module provides a comprehensive hyperv integration with subcommands for:
//! - `run`: Run a bootable container as a persistent VM

use clap::Subcommand;

pub mod run;

/// hyperv subcommands for managing bootc disk images and domains
#[derive(Debug, Subcommand)]
pub enum HypervSubcommands {
    /// Run a bootable container as a persistent VM
    Run(run::HypervRunOpts),
}
