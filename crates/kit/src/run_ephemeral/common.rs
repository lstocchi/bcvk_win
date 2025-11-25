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
