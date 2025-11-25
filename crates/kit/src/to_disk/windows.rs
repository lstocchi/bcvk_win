use crate::to_disk::ToDiskOpts;
use camino::Utf8Path;
use color_eyre::eyre::{Context, Ok, Result};
use std::process::Command;
use tracing::debug;

pub fn run(opts: ToDiskOpts) -> Result<()> {
    // Phase 0: Check for existing cached disk image
    /* let would_reuse = if opts.target_disk.exists() {
        debug!("Target disk image already exists: {}", opts.target_disk);

        // Get the image digest for comparison
        let inspect = crate::images::inspect(&opts.source_image)?;
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
    } */

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

    let target_tmp_disk = opts
        .target_disk
        .with_extension(opts.additional.format.as_str());
    match opts.additional.format {
        crate::to_disk::Format::Raw => {
            // Create sparse file - only allocates space as data is written
            let file = std::fs::File::create(&target_tmp_disk)
                .with_context(|| format!("Opening {}", target_tmp_disk))?;
            file.set_len(disk_size)?;
            // TODO pass to qemu via fdset
            drop(file);
        }
        crate::to_disk::Format::Qcow2 => {
            println!("Qcow2 format");
        }
    }

    // Phase 3: Installation command generation
    // Generate complete script including storage setup and bootc install
    //let bootc_install_command = opts.generate_bootc_install_command(disk_size)?;

    let container_mount_point = "/output.raw";
    // Prepare bootc args
    let mut bootc_cmd = vec![
        "bootc",
        "install",
        "to-disk",
        "--via-loopback",
        "--generic-image",
        "--skip-fetch-check",
        "--filesystem",
        "xfs",
    ];

    let install_args = opts.install.to_bootc_args();
    bootc_cmd.extend(install_args.iter().map(|s| s.as_str()));

    // Add the target device (the file we mounted)
    bootc_cmd.push(container_mount_point);

    let volume_arg = format!("{}:{}", target_tmp_disk.to_string(), container_mount_point);
    let podman_args = vec![
        "run",
        "--rm",
        "--privileged", // Required for loopback mounting/formatting
        "--pid=host",   // Performance
        "--security-opt",
        "label=disable", // Allow writing to volume
        "-v",
        &volume_arg,
        &opts.source_image,
    ];

    // Combine
    let mut full_args = podman_args;
    full_args.extend(bootc_cmd);

    println!("full_args: {:?}", full_args);
    let output = Command::new("podman")
        .args(full_args)
        .output()
        .expect("Failed to run podman run");
    assert!(
        output.status.success(),
        "Failed to run bootc install: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // convert to vhdx
    let vhdx_mount_point = "/work";
    let target_tmp_disk_name = target_tmp_disk.file_name().unwrap().to_string();
    let target_disk_name = opts.target_disk.file_name().unwrap().to_string();
    let vhdx_volume_arg = format!(
        "{}:{}",
        opts.target_disk
            .parent()
            .unwrap_or(Utf8Path::new("."))
            .to_string(),
        vhdx_mount_point
    );
    let vhdx_convert_cmd = format!(
        "dnf install -y qemu-img && qemu-img convert -f raw -O vhdx {}/{} {}/{}",
        vhdx_mount_point, target_tmp_disk_name, vhdx_mount_point, target_disk_name
    );
    let vhdx_cmd = vec![
        "run",
        "--rm",
        "-v",
        &vhdx_volume_arg,
        &opts.source_image,
        "sh",
        "-c",
        &vhdx_convert_cmd,
    ];
    println!("vhdx_cmd: {:?}", vhdx_cmd);
    let output = Command::new("podman")
        .args(vhdx_cmd)
        .output()
        .expect("Failed to run podman run");
    assert!(
        output.status.success(),
        "Failed to convert to vhdx: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
