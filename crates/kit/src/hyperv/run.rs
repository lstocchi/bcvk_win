use crate::{common_opts::MemoryOpts, utils::parse_memory_to_mb};
use clap::Parser;
use color_eyre::{eyre::{eyre, Context}, Result};
use tracing::debug;
use std::process::Command;
use camino::Utf8PathBuf;

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

/// Find the user-data script file, searching from current directory up to project root
fn find_user_data_script() -> Result<Utf8PathBuf> {
    let current_dir = std::env::current_dir()
        .context("Failed to get current directory")?;
    
    // Try relative to current directory first
    let script_path = current_dir.join("crates").join("kit").join("scripts").join("user-data");
    if script_path.exists() {
        return Ok(Utf8PathBuf::from_path_buf(script_path)
            .map_err(|_| eyre!("Path is not valid UTF-8"))?);
    }
    
    // Try scripts/user-data relative to current directory
    let script_path = current_dir.join("scripts").join("user-data");
    if script_path.exists() {
        return Ok(Utf8PathBuf::from_path_buf(script_path)
            .map_err(|_| eyre!("Path is not valid UTF-8"))?);
    }
    
    // Try to find project root by looking for Cargo.toml
    let mut search_dir = current_dir.as_path();
    while let Some(parent) = search_dir.parent() {
        let cargo_toml = parent.join("Cargo.toml");
        if cargo_toml.exists() {
            let script_path = parent.join("crates").join("kit").join("scripts").join("user-data");
            if script_path.exists() {
                return Ok(Utf8PathBuf::from_path_buf(script_path)
                    .map_err(|_| eyre!("Path is not valid UTF-8"))?);
            }
        }
        search_dir = parent;
    }
    
    Err(eyre!("Could not find scripts/user-data file. Searched from: {}", current_dir.display()))
}

/// Wrapper to run podman commands cleanly
fn run_macadam(args: &[&str], desc: &str) -> Result<()> {
    debug!("Running: macadam {:?}", args);
    // On Windows, "macadam" resolves to macadam.exe
    let status = Command::new("macadam")
        .args(args)
        .status()
        .context(format!("Failed to execute macadam for {}", desc))?;

    if !status.success() {
        return Err(eyre!("Macadam command failed for {}", desc));
    }
    Ok(())
}

pub fn run(opts: HypervRunOpts) -> Result<()> {

    let memory = opts.resolved_memory_mb()?.to_string();
    let cpus = opts.cpus.to_string();
    let disk_size = opts.disk_size.to_string();
    let user_data_path = find_user_data_script()?;

    let mut macadam_args = vec![
        "init",
        "--memory", memory.as_str(),
        "--cpus", cpus.as_str(),
        "--disk-size", disk_size.as_str(),
        "--provider", "hyperv",
        "--cloud-init", user_data_path.as_str(),
        "--username", "test",
        "--ssh-identity-path", "C:\\Users\\baldr\\.ssh\\id_ed25519",
        opts.image.as_str(),
    ];

    if let Some(name) = &opts.name {
        macadam_args.push("--name");
        macadam_args.push(name.as_str());
    }
    println!("opts: {:?}", macadam_args);

    run_macadam(&macadam_args, "hyperv create vm")?;

    let mut macadam_args = vec![
        "start",
        "--provider", "hyperv",
    ];
    if let Some(name) = &opts.name {
        macadam_args.push(name.as_str());
    }
    run_macadam(&macadam_args, "hyperv start vm")?;


    let mut macadam_args = vec![
        "ssh",
        "--provider", "hyperv",
    ];
    if let Some(name) = &opts.name {
        macadam_args.push(name.as_str());
    }
    run_macadam(&macadam_args, "hyperv ssh to vm")?;

    Ok(())
}