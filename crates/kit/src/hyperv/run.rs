//! hyperv run command - run a bootable container as a VM
//!
//! This module provides the core functionality for creating and managing
//! hyperv-based VMs from bootc container images.

use crate::utils::{generate_unique_vm_name, CommandRunExt};
use crate::{common_opts::MemoryOpts, utils::parse_memory_to_mb};
use clap::Parser;
use color_eyre::{
    eyre::{eyre, Context},
    Result,
};
use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::debug;

/// Options for creating and running a bootable container VM
#[derive(Debug, Parser)]
pub struct HypervRunOpts {
    pub image: String,

    #[clap(long)]
    pub name: Option<String>,

    #[clap(flatten)]
    pub memory: MemoryOpts,

    #[clap(long, default_value = "8")]
    pub cpus: u32,

    #[clap(long, default_value = "20")]
    pub disk_size: u64,
}

impl HypervRunOpts {
    pub fn resolved_memory_mb(&self) -> Result<u32> {
        parse_memory_to_mb(&self.memory.memory)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HypervListEntry {
    pub name: String,
    pub image: String,
}

/// Wrapper to run macadam commands cleanly
fn run_macadam(args: &[&str], command_name: &str) -> Result<()> {
    debug!("Running: macadam {:?}", args);
    // On Windows, "macadam" resolves to macadam.exe
    let status = Command::new("macadam")
        .args(args)
        .status()
        .context(format!(
            "Failed to execute macadam {} command",
            command_name
        ))?;

    if !status.success() {
        return Err(eyre!(
            "Failed to run macadam {} command on hyperv VM",
            command_name
        ));
    }
    Ok(())
}

fn get_existing_vm_names() -> Result<Vec<String>> {
    let output: Vec<HypervListEntry> = Command::new("macadam")
        .args(&["list", "--provider", "hyperv", "--format", "json"])
        .run_and_parse_json()
        .map_err(|e| eyre!("Failed to list existing hyperv vms: {}", e))?;

    Ok(output.iter().map(|entry| entry.name.clone()).collect())
}

pub fn run(opts: HypervRunOpts) -> Result<()> {
    let existing_vms = get_existing_vm_names()?;

    let vm_name = match &opts.name {
        Some(name) => name.clone(),
        None => generate_unique_vm_name(&opts.image, &existing_vms),
    };

    let memory = opts.resolved_memory_mb()?.to_string();
    let cpus = opts.cpus.to_string();
    let disk_size = opts.disk_size.to_string();

    let init_args = vec![
        "init",
        "--memory",
        &memory,
        "--cpus",
        &cpus,
        "--disk-size",
        &disk_size,
        "--provider",
        "hyperv",
        "--name",
        &vm_name,
        opts.image.as_str(),
    ];

    println!("opts: {:?}", init_args);
    run_macadam(&init_args, "init")?;

    let start_args = vec!["start", "--provider", "hyperv", &vm_name];
    run_macadam(&start_args, "start")?;

    let macadam_args = vec!["ssh", "--provider", "hyperv", &vm_name];
    run_macadam(&macadam_args, "ssh")?;

    Ok(())
}
