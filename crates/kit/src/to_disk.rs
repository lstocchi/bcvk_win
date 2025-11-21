//! Install bootc images to disk using ephemeral VMs
//!
//! This module provides the core installation functionality for bcvk, enabling
//! automated installation of bootc container images to disk images through an
//! ephemeral VM-based approach.
//!
//! # Installation Workflow
//!
//! The bootc installation process follows these key steps:
//!
//! 1. **Image Preparation**: Validates the source container image and prepares the
//!    target disk file, creating it with appropriate sizing if it doesn't exist
//!
//! 2. **Storage Configuration**: Sets up container storage access within the
//!    installation VM by mounting the host's container storage as read-only
//!
//! 3. **Ephemeral VM Launch**: Creates a temporary VM using the bootc image itself
//!    as the installation environment, with the target disk attached via virtio-blk
//!
//! 4. **Bootc Installation**: Executes `bootc install to-disk` within the VM,
//!    installing the container image to the attached disk with the specified
//!    filesystem and configuration options
//!
//! 5. **Cleanup**: The ephemeral VM automatically shuts down after installation,
//!    leaving behind the configured disk image ready for deployment
//!
//! # Disk Image Management
//!
//! The installation process creates and manages disk images as follows:
//!
//! - **Automatic Sizing**: Target disk size is calculated as 2x the source image
//!   size with a 4GB minimum to ensure adequate space for installation
//!
//! - **File Creation**: Creates sparse disk image files that grow as needed,
//!   supporting efficient storage usage
//!
//! - **Virtio-blk Attachment**: Attaches the target disk to the VM using virtio-blk
//!   with a predictable device name (`/dev/disk/by-id/virtio-output`)
//!
//! # Filesystem and Storage Options
//!
//! The module supports multiple filesystem types and storage configurations:
//!
//! - **Filesystem Types**: ext4 (default), xfs, and btrfs filesystems
//! - **Custom Root Size**: Optional specification of root filesystem size
//! - **Storage Path Detection**: Automatic detection of host container storage or
//!   manual specification for custom setups
//!
//! # Ephemeral VM Integration
//!
//! This module leverages the ephemeral VM infrastructure (`run_ephemeral`) to:
//!
//! - **Isolated Environment**: Provides a clean, isolated environment for
//!   installation without affecting the host system
//!
//! - **Container Storage Access**: Mounts host container storage read-only to
//!   access the source image without network dependencies
//!
//! - **Automated Lifecycle**: Handles VM startup, installation execution, and
//!   cleanup automatically with proper error handling
//!
//! - **Debug Support**: Provides comprehensive logging and debug output for
//!   troubleshooting installation issues
//!
//! # Usage Examples
//!
//! ```bash
//! # Basic installation with defaults
//! bcvk to-disk quay.io/centos-bootc/centos-bootc:stream10 output.img
//!
//! # Custom filesystem and size
//! bcvk to-disk --filesystem xfs --root-size 20G \
//!     quay.io/centos-bootc/centos-bootc:stream10 output.img
//! 
use crate::install_options::InstallOptions;
use crate::run_ephemeral::CommonVmOpts;
use crate::{cache_metadata, images, utils};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, ValueEnum};
use color_eyre::eyre::{eyre, Context};
use color_eyre::Result;
use indoc::indoc;
use tracing::debug;
use std::process::Command;

/// Supported disk image formats
#[derive(Debug, Clone, ValueEnum, PartialEq, Default)]
pub enum Format {
    /// Raw disk image format (default)
    #[default]
    Raw,
    /// QEMU Copy On Write 2 format
    Qcow2,
    Vhd,
}

impl Format {
    /// Get the string representation for qemu-img
    pub fn as_str(&self) -> &'static str {
        match self {
            Format::Raw => "raw",
            Format::Qcow2 => "qcow2",
            Format::Vhd => "vhd",
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
    /* fn get_storage_path(&self) -> Result<Utf8PathBuf> {
        if let Some(ref path) = self.install.storage_path {
            utils::validate_container_storage_path(path)?;
            Ok(path.clone())
        } else {
            utils::detect_container_storage_path()
        }
    } */

   /// Generate the complete bootc installation command arguments for SSH execution
   fn generate_bootc_install_command(&self, disk_size: u64) -> Result<Vec<String>> {
        let source_imgref = format!("containers-storage:{}", self.source_image);

        // Quote each bootc argument individually to prevent shell injection
        let mut quoted_bootc_args = Vec::new();
        for arg in self.install.to_bootc_args() {
            let quoted = shlex::try_quote(&arg)
                .map_err(|e| eyre!("Failed to quote bootc argument '{}': {}", arg, e))?;
            quoted_bootc_args.push(quoted.to_string());
        }
        let bootc_args = quoted_bootc_args.join(" ");

        // Quote the source image reference to prevent shell injection
        let quoted_source_imgref = shlex::try_quote(&source_imgref)
            .map_err(|e| eyre!("Failed to quote source imgref '{}': {}", source_imgref, e))?
            .to_string();

        let install_log = self
            .additional
            .install_log
            .as_deref()
            .map(|v| shlex::try_quote(v))
            .transpose()?
            .map(|v| format!("--env=RUST_LOG={v}"))
            .unwrap_or_default();

        // Size /var/tmp tmpfs to match swap size (disk_size)
        // This avoids duplicating size calculation logic
        let tmpfs_size_str = format!("size={}k", disk_size / 1024);
        let tmpfs_size_quoted = shlex::try_quote(&tmpfs_size_str)
            .map_err(|e| eyre!("Failed to quote tmpfs size: {}", e))?
            .to_string();

        // Create the complete script by substituting variables directly
        let script = indoc! {r#"
            set -euo pipefail

            echo "Setting up temporary filesystems..."
            # Mount /var/tmp as a large tmpfs, then symlink /var/lib/containers to it
            # to consolidate temporary storage in one location
            mount -t tmpfs -o {TMPFS_SIZE} tmpfs /var/tmp
            mkdir -p /var/tmp/containers
            rm /var/lib/containers -rf
            ln -sr /var/tmp/containers /var/lib/containers

            # Ensure virtiofs mount is available (fallback for older systemd without SMBIOS support)
            AIS=/run/virtiofs-mnt-hoststorage/
            if ! mountpoint -q ${AIS} &>/dev/null; then
                echo "virtiofs mount not found at ${AIS}, mounting manually..."
                mkdir -p ${AIS}
                mount -t virtiofs mount_hoststorage ${AIS} -o ro
            fi

            echo "Starting bootc installation..."
            echo "Source image: {SOURCE_IMGREF}"
            echo "Additional args: {BOOTC_ARGS}"

            tty=
            if test -t 0; then
                tty=--tty
            fi

            # Execute bootc installation, having the outer podman pull from
            # the virtiofs store on the host, as well as the inner bootc.
            # Mount /var/tmp into inner container to avoid cross-device link errors (issue #125)
            export STORAGE_OPTS=additionalimagestore=${AIS}
            podman run --rm -i ${tty} --privileged --pid=host --net=none -v /sys:/sys:ro \
                -v /var/lib/containers:/var/lib/containers -v /var/tmp:/var/tmp -v /dev:/dev -v ${AIS}:${AIS} --security-opt label=type:unconfined_t \
                --env=STORAGE_OPTS \
                {INSTALL_LOG} \
                {SOURCE_IMGREF} \
                bootc install to-disk \
                --generic-image \
                --skip-fetch-check \
                {BOOTC_ARGS} \
                /dev/disk/by-id/virtio-output

            echo "Installation completed successfully!"
        "#}
        .replace("{TMPFS_SIZE}", &tmpfs_size_quoted)
        .replace("{SOURCE_IMGREF}", &quoted_source_imgref)
        .replace("{INSTALL_LOG}", &install_log)
        .replace("{BOOTC_ARGS}", &bootc_args);

        println!("script: {}", script);
        Ok(vec!["/bin/bash".to_string(), "-c".to_string(), script])
    }

    /// Calculate the optimal target disk size based on the source image or explicit size
    ///
    /// Returns explicit disk_size if provided (parsed from human-readable format),
    /// otherwise 2x the image size with a 4GB minimum.
    fn calculate_disk_size(&self) -> Result<u64> {
        if let Some(ref size_str) = self.additional.disk_size {
            let parsed = utils::parse_size(size_str)?;
            debug!("Using explicit disk size: {} -> {} bytes", size_str, parsed);
            return Ok(parsed);
        }

        // Get the image size and multiply by 2 for installation space
        let image_size = images::get_image_size(&self.source_image)?;
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

/// Execute a bootc installation using an ephemeral VM with SSH
///
/// Main entry point for the bootc installation process. See module-level documentation
/// for details on the installation workflow and architecture.
pub fn run(opts: ToDiskOpts) -> Result<()> {
    // Phase 0: Check for existing cached disk image 
    let would_reuse = if opts.target_disk.exists() {
        debug!("Target disk image already exists: {}", opts.target_disk);

        // Get the image digest for comparison
        let inspect = images::inspect(&opts.source_image)?;
        let image_digest = inspect.digest.to_string();

        match cache_metadata::check_cached_disk(&opts.target_disk.as_std_path(), &image_digest, &opts.source_image, &opts.install)? {
            Ok(()) => {
                if opts.additional.dry_run {
                    println!("would-reuse");
                    return Ok(());
                }
                println!(
                    "Reusing existing cached disk image (digest {image_digest}) at: {}",
                    opts.target_disk
                );
                return Ok(());
            }
            Err(e) => {
                debug!("Existing disk does not match requirements, recreating: {e}");
                if !opts.additional.dry_run {
                    // Remove the existing disk so we can recreate it
                    std::fs::remove_file(&opts.target_disk).with_context(|| {
                        format!("Failed to remove existing disk {}", opts.target_disk)
                    })?;
                }
                false
            }
        }
    } else {
        false
    };

    // In dry-run mode, report whether we would regenerate
    if opts.additional.dry_run {
        if would_reuse {
            println!("would-reuse");
        } else {
            println!("would-regenerate");
        }
        return Ok(());
    }

    // Phase 1: Validation and preparation
    // Resolve container storage path (auto-detect or validate specified path)
    //let storage_path = opts.get_storage_path()?;

    // Debug logging for installation configuration
    if opts.additional.common.debug {
        //debug!("Using container storage: {:?}", storage_path);
        debug!("Installing to target disk: {:?}", opts.target_disk);
        debug!("Filesystem: {:?}", opts.install.filesystem);
        if let Some(ref root_size) = opts.install.root_size {
            debug!("Root size: {}", root_size);
        }
    }

    let disk_size = opts.calculate_disk_size()?;
    println!("disk_size: {}", disk_size);

    let target_tmp_disk = opts.target_disk.with_extension(opts.additional.format.as_str());
    match opts.additional.format {
        Format::Raw => {
            // Create sparse file - only allocates space as data is written
            let file = std::fs::File::create(&target_tmp_disk)
                .with_context(|| format!("Opening {}", target_tmp_disk))?;
            file.set_len(disk_size)?;
            // TODO pass to qemu via fdset
            drop(file);
        }
        Format::Qcow2 => {
            println!("Qcow2 format");
        }
        Format::Vhd => {
            println!("Vhd format");
        }
    }

    // Phase 3: Installation command generation
    // Generate complete script including storage setup and bootc install
    //let bootc_install_command = opts.generate_bootc_install_command(disk_size)?;

    let container_mount_point = "/output.raw";
    // Prepare bootc args
    let mut bootc_cmd = vec![
        "bootc", "install", "to-disk",
        "--via-loopback",
        "--generic-image",
        "--skip-fetch-check",
        "--filesystem", "xfs",
    ];

    let install_args = opts.install.to_bootc_args();
    bootc_cmd.extend(install_args.iter().map(|s| s.as_str()));
    
    // Add the target device (the file we mounted)
    bootc_cmd.push(container_mount_point);

    let volume_arg = format!("{}:{}", target_tmp_disk.to_string(), container_mount_point);
    let podman_args = vec![
        "run", "--rm", 
        "--privileged",                // Required for loopback mounting/formatting
        "--pid=host",                  // Performance
        "--security-opt", "label=disable", // Allow writing to volume
        "-v", &volume_arg,
        &opts.source_image,
    ];

    // Combine
    let mut full_args = podman_args;
    full_args.extend(bootc_cmd);

    println!("full_args: {:?}", full_args);
    run_podman(&full_args, "bootc installation")?;

    // convert to vhdx
    let vhdx_mount_point = "/work";
    let target_tmp_disk_name = target_tmp_disk.file_name().unwrap().to_string();
    let target_disk_name = opts.target_disk.file_name().unwrap().to_string();
    let vhdx_volume_arg = format!("{}:{}", opts.target_disk.parent().unwrap_or(Utf8Path::new(".")).to_string(), vhdx_mount_point);
    let vhdx_convert_cmd = format!("dnf install -y qemu-img && qemu-img convert -f raw -O vhdx {}/{} {}/{}", vhdx_mount_point, target_tmp_disk_name, vhdx_mount_point, target_disk_name);
    let vhdx_cmd = vec![
        "run", "--rm", "-v", &vhdx_volume_arg,  
        &opts.source_image, "sh", "-c",
        &vhdx_convert_cmd,
    ];
    println!("vhdx_cmd: {:?}", vhdx_cmd);
    run_podman(&vhdx_cmd, "convert to vhdx")?; 

    /*
    let container_mount_point = "/output/";
    let target_dir = opts.target_disk.parent().unwrap_or(Utf8Path::new("."));
    let volume_arg = format!("{}:{}", target_dir.to_string(), container_mount_point);
    let podman_args = vec![
        "run", "--rm", 
        "--privileged",
        "--security-opt", "label=unconfined_t",
        "-v", &volume_arg,
        "-v",
        "/var/lib/containers/storage:/var/lib/containers/storage",
        "-v",
        "C:\\Users\\baldr\\Work\\bootc\\config.json:/config.json:ro",
        "--label",
        "bootc.image.builder=true",
        "quay.io/centos-bootc/bootc-image-builder:latest",
        &opts.source_image,
        "--output",
        container_mount_point,
        "--local",
        "--progress",
        "verbose",
        "--type",
        "vhd",
        "--target-arch",
        "amd64",
        "--rootfs",
        "xfs",
    ];*/

   // run_podman(&podman_args, "convert to vhdx")?;

    // move the file to the original name
    //td::fs::rename(target_dir.join("vpc/disk.vhd"), opts.target_disk)?;

    Ok(())
}

/// Wrapper to run podman commands cleanly
fn run_podman(args: &[&str], desc: &str) -> Result<()> {
    debug!("Running: podman {:?}", args);
    // On Windows, "podman" resolves to podman.exe
    let status = Command::new("podman")
        .args(args)
        .status()
        .context(format!("Failed to execute podman for {}", desc))?;

    if !status.success() {
        return Err(eyre!("Podman command failed for {}", desc));
    }
    Ok(())
}
