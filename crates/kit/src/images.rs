//! Image management and inspection utilities for bootc containers.
//!
//! Provides functionality for listing and inspecting bootc container images through
//! podman integration with both table and JSON output formats.
//! 
use std::process::Command;
use color_eyre::eyre::{Context, Result, eyre};
use comfy_table::{presets::UTF8_FULL, Table};
use serde::{Deserialize, Serialize};

use crate::command_run::CommandRun;

/// Command-line options for image management operations.
#[derive(clap::Subcommand, Debug)]
pub(crate) enum ImagesOpts {
    /// List all available bootc container images on the system
    List {
        /// Output as structured JSON instead of table format
        #[clap(long)]
        json: bool,
    },
}

impl ImagesOpts {
    pub(crate) fn run(self) -> Result<()> {
        match self {
            ImagesOpts::List { json } => {
                let images = list()?;

                if json {
                    let json_output = serde_json::to_string_pretty(&images)?;
                    println!("{}", json_output);
                } else {
                    // Create a table using comfy_table
                    let mut table = Table::new();
                    table.load_preset(UTF8_FULL).set_header(vec![
                        "REPOSITORY",
                        "TAG",
                        "IMAGE ID",
                        "CREATED",
                        "SIZE",
                    ]);

                    for image in images {
                        let (repository, tag) = if let Some(names) = &image.names {
                            if let Some(name) = names.first() {
                                if let Some((repo, tag)) = name.rsplit_once(':') {
                                    (repo.to_string(), tag.to_string())
                                } else {
                                    (name.to_string(), "latest".to_string())
                                }
                            } else {
                                ("<none>".to_string(), "<none>".to_string())
                            }
                        } else {
                            ("<none>".to_string(), "<none>".to_string())
                        };

                        let id = if image.id.len() > 12 {
                            &image.id[..12]
                        } else {
                            &image.id
                        };

                        let created = image
                            .created_at
                            .map(|dt| format_relative_time(dt))
                            .unwrap_or_else(|| "N/A".to_string());

                        let size = indicatif::BinaryBytes(image.size).to_string();

                        table.add_row(vec![repository, tag, id.to_string(), created, size]);
                    }

                    println!("{}", table);
                }
                Ok(())
            }
        }
    }
}

/// Single bootc container image entry from podman images output.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageListEntry {
    /// Repository names and tags, None for dangling images
    pub names: Option<Vec<String>>,

    /// SHA256 image identifier
    pub id: String,

    /// Image size in bytes
    pub size: u64,

    /// Image creation timestamp
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Container image inspection data from podman image inspect.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageInspect {
    /// SHA256 image identifier
    pub id: String,

    /// Image digest
    pub digest: oci_spec::image::Digest,

    /// Image size in bytes
    pub size: u64,

    /// Image creation timestamp
    pub created: Option<chrono::DateTime<chrono::Utc>>,
}

/// Format a datetime as relative time (e.g., "2 hours ago", "3 days ago").
fn format_relative_time(dt: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(dt);

    if duration.num_seconds() < 60 {
        format!("{} seconds ago", duration.num_seconds())
    } else if duration.num_minutes() < 60 {
        let mins = duration.num_minutes();
        if mins == 1 {
            "1 minute ago".to_string()
        } else {
            format!("{} minutes ago", mins)
        }
    } else if duration.num_hours() < 24 {
        let hours = duration.num_hours();
        if hours == 1 {
            "1 hour ago".to_string()
        } else {
            format!("{} hours ago", hours)
        }
    } else if duration.num_days() < 30 {
        let days = duration.num_days();
        if days == 1 {
            "1 day ago".to_string()
        } else {
            format!("{} days ago", days)
        }
    } else if duration.num_days() < 365 {
        let months = duration.num_days() / 30;
        if months == 1 {
            "1 month ago".to_string()
        } else {
            format!("{} months ago", months)
        }
    } else {
        let years = duration.num_days() / 365;
        if years == 1 {
            "1 year ago".to_string()
        } else {
            format!("{} years ago", years)
        }
    }
}

/// List all bootc container images using podman.
#[allow(dead_code)]
pub fn list() -> Result<Vec<ImageListEntry>> {
    let images: Vec<ImageListEntry> = Command::new("podman")
        .args([
            "images",
            "--format",
            "json",
            "--filter=label=containers.bootc=1",
        ])
        .run_and_parse_json()
        .map_err(|e| eyre!("{e}"))?;
    Ok(images)
}

/// Inspect a container image and return metadata.
pub fn inspect(name: &str) -> Result<ImageInspect> {
    let mut r: Vec<ImageInspect> = Command::new("podman")
        .args(["image", "inspect", name])
        .run_and_parse_json()
        .map_err(|e| eyre!("{e}"))?;

    r.pop().ok_or_else(|| eyre!("No such image"))
}

/// Get container image size in bytes for disk space planning.
pub fn get_image_size(name: &str) -> Result<u64> {
    tracing::debug!("Getting size for image: {}", name);
    let info = inspect(name)?;
    tracing::debug!("Found image size: {} bytes", info.size);
    Ok(info.size)
}

