//! Bootc Virtualization Kit for Windows(bcvk_win) - A toolkit for bootc containers and local virtualization

use clap::{Parser, Subcommand};
use color_eyre::{eyre::Context as _, Report, Result};

mod cache_metadata;
mod command_run;
mod common_opts;
mod hyperv;
mod images;
mod install_options;
mod instancetypes;
mod run_ephemeral;
mod to_disk;
mod utils;


/// A comprehensive toolkit for bootc containers and local virtualization.
///
/// bcvk provides a complete workflow for building, testing, and managing
/// bootc containers using ephemeral VMs. Run bootc images as temporary VMs,
/// install them to disk, or manage existing installations - all without
/// requiring root privileges.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available bcvk_win commands for container and VM management.
#[derive(Subcommand)]
enum Commands {
    #[clap(subcommand)]
    Images(images::ImagesOpts),

    /// Install bootc images to persistent disk images
    #[clap(name = "to-disk")]
    ToDisk(to_disk::ToDiskOpts),

    Hyperv {
        #[command(subcommand)]
        command: hyperv::HypervSubcommands,
    },
}

/// Install and configure the tracing/logging system.
///
/// Sets up structured logging with environment-based filtering,
/// error layer integration, and console output formatting.
/// Logs are filtered by RUST_LOG environment variable, defaulting to 'info'.
fn install_tracing() {
    use tracing_error::ErrorLayer;
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::EnvFilter;

    let format = fmt::format().without_time().with_target(false).compact();

    let fmt_layer = fmt::layer()
        .event_format(format)
        .with_writer(std::io::stderr);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(ErrorLayer::default())
        .init();
}

/// Main entry point for the bcvk_win CLI application.
///
/// Initializes logging, error handling, and command dispatch for all
/// bcvk operations including VM management, SSH access, and
/// container image handling.
fn main() -> Result<(), Report> {
    install_tracing();
    color_eyre::install()?;

    let cli = Cli::parse();


    match cli.command {
        Commands::Images(opts) => opts.run()?,
        Commands::ToDisk(opts) => to_disk::run(opts)?,
        Commands::Hyperv { command } => {
            match command {
                hyperv::HypervSubcommands::Run(opts) => hyperv::run::run(opts)?,
            }
        }
    }
    tracing::debug!("exiting");

    std::process::exit(0);
}
