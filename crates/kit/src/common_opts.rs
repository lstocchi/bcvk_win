//! Common CLI options shared across commands

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const DEFAULT_MEMORY_USER_STR: &str = "4G";

/// Memory size options
#[derive(Parser, Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryOpts {
    #[clap(
        long,
        default_value = DEFAULT_MEMORY_USER_STR,
        help = "Memory size (e.g. 4G, 2048M, or plain number for MB)"
    )]
    pub memory: String,
}

impl fmt::Display for MemoryOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.memory)
    }
}
