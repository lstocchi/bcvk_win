//! Ephemeral VM execution using hybrid container-VM approach.
//!
//! This module implements a sophisticated architecture for running container images as
//! ephemeral VMs by orchestrating a multi-stage execution flow through privileged
//! containers, namespace isolation, and VirtioFS filesystem sharing.
//!
//! # Architecture Overview
//!
//! The system uses a "hybrid container-VM" approach that runs QEMU inside privileged
//! Podman containers with KVM access. This combines container isolation with full
//! kernel VM capabilities.
//!
//! ## Execution Flow
//!
//! The execution follows this chain:
//! 1. **Host Process**: `bcvk run-ephemeral` invoked on host
//! 2. **Container Launch**: Podman privileged container with KVM and host mounts
//! 3. **Namespace Setup**: bwrap creates isolated namespace with hybrid rootfs  
//! 4. **Binary Re-execution**: Same binary re-executes with `container-entrypoint`
//! 5. **VM Launch**: QEMU starts with VirtioFS root and additional mounts
//!
//! ## Key Components
//!
//! ### Phase 1: Container Setup (`run_qemu_in_container`)
//! - Runs on the host system
//! - Serializes CLI options to JSON via `BCK_CONFIG` environment variable
//! - Mounts critical resources into container:
//!   - `/run/selfexe`: The bcvk binary itself (for re-execution)
//!   - `/run/source-image`: Target container image via `--mount=type=image`
//!   - `/run/hostusr`: Host `/usr` directory (read-only, for QEMU/tools)
//!   - `/var/lib/bcvk/entrypoint`: Embedded entrypoint.sh script
//! - Handles real-time output streaming for `--execute` commands
//!
//! ### Phase 2: Hybrid Rootfs Creation (entrypoint.sh)
//! The entrypoint script creates a hybrid root filesystem at `/run/tmproot`:
//! ```text
//! /run/tmproot/
//! ├── usr/       → bind mount to /run/hostusr (host binaries)
//! ├── bin/       → symlink to usr/bin
//! ├── lib/       → symlink to usr/lib
//! └── [other dirs created empty for container compatibility]
//! ```
//!
//! ### Phase 3: Namespace Isolation (bwrap)
//! Uses bubblewrap to create isolated namespace:
//! - New mount namespace with `/run/tmproot` as root
//! - Shared `/run/inner-shared` for virtiofsd socket communication
//! - Proper `/proc`, `/dev`, `/tmp` mounts
//! - Re-executes binary: `bwrap ... -- /run/selfexe container-entrypoint`
//!
//! ### Phase 4: VM Execution (`run_impl`)
//! - Runs inside the container after namespace setup
//! - Extracts kernel/initramfs from container image
//! - Spawns virtiofsd daemons for filesystem sharing:
//!   - Main daemon: shares `/run/source-image` as VM root
//!   - Additional daemons: one per host mount (`--bind`/`--ro-bind`)
//! - Generates systemd `.mount` units for virtiofs mounts
//! - Configures and launches QEMU with VirtioFS root
//!
//! ## VirtioFS Architecture
//!
//! The system uses VirtioFS for high-performance filesystem sharing:
//! - **Root FS**: Container image mounted via main virtiofsd at `/run/inner-shared/virtiofs.sock`
//! - **Host Mounts**: Separate virtiofsd per mount at `/run/inner-shared/virtiofs-<name>.sock`
//! - **VM Access**: Mounts appear at `/run/virtiofs-mnt-<name>` via systemd units
//!
//! ## Command Execution (`--execute`)
//!
//! For running commands inside the VM:
//! 1. Creates systemd services (`bootc-execute.service`, `bootc-execute-finish.service`)
//! 2. Uses VirtioSerial devices for output (`execute`) and status (`executestatus`)
//! 3. Streams output in real-time via monitoring thread on host
//! 4. Captures exit codes via systemd service status
//!
//! ## Security Model
//!
//! - **Privileged Container**: Required for KVM and namespace operations
//! - **Read-only Host Access**: Host `/usr` mounted read-only
//! - **SELinux**: Disabled within container only (`--security-opt=label=disable`)
//! - **Network Isolation**: Default "none" unless explicitly configured
//! - **VirtioFS Sandboxing**: Relies on VM isolation for security
//!
//! ## Configuration Passing
//!
//! All CLI options are preserved through the execution chain via JSON serialization:
//! - Host serializes `RunEphemeralOpts` to `BCK_CONFIG` environment variable
//! - Container entrypoint deserializes and re-applies all settings
//! - Ensures perfect fidelity of user options across process boundaries

use crate::common_opts::MemoryOpts;
use clap::Parser;
use serde::{Deserialize, Serialize};

/// Common VM configuration options for hardware, networking, and features.
#[derive(Parser, Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommonVmOpts {
    #[clap(
        long,
        help = "Instance type (e.g., u1.nano, u1.small, u1.medium). Overrides vcpus/memory if specified."
    )]
    pub itype: Option<crate::instancetypes::InstanceType>,

    #[clap(flatten)]
    pub memory: MemoryOpts,

    #[clap(long, help = "Number of vCPUs (overridden by --itype if specified)")]
    pub vcpus: Option<u32>,

    #[clap(long, help = "Enable console output to terminal for debugging")]
    pub console: bool,

    #[clap(
        long,
        help = "Enable debug mode (drop to shell instead of running QEMU)"
    )]
    pub debug: bool,

    #[clap(
        long = "virtio-serial-out",
        value_name = "NAME:FILE",
        help = "Add virtio-serial device with output to file (format: name:/path/to/file)"
    )]
    pub virtio_serial_out: Vec<String>,

    #[clap(
        long,
        help = "Execute command inside VM via systemd and capture output"
    )]
    pub execute: Vec<String>,

    #[clap(
        long,
        short = 'K',
        help = "Generate SSH keypair and inject via systemd credentials"
    )]
    pub ssh_keygen: bool,
}