use color_eyre::eyre::{eyre, Context};
use color_eyre::Result;

/// Convert a unit string to bytes multiplier
/// Handles libvirt-style units distinguishing between decimal (KB, MB, GB - powers of 1000)
/// and binary (KiB, MiB, GiB - powers of 1024) units per libvirt specification
pub fn unit_to_bytes(unit: &str) -> Option<u128> {
    match unit {
        // Binary prefixes (powers of 1024)
        "B" | "bytes" => Some(1),
        "k" | "K" | "KiB" => Some(1024),
        "M" | "MiB" => Some(1024u128.pow(2)),
        "G" | "GiB" => Some(1024u128.pow(3)),
        "T" | "TiB" => Some(1024u128.pow(4)),

        // Decimal prefixes (powers of 1000)
        "KB" => Some(1_000),
        "MB" => Some(1_000u128.pow(2)),
        "GB" => Some(1_000u128.pow(3)),
        "TB" => Some(1_000u128.pow(4)),

        _ => None,
    }
}

/// Parse a memory string (like "2G", "1024M", "512") to megabytes
pub fn parse_memory_to_mb(memory_str: &str) -> Result<u32> {
    let memory_str = memory_str.trim();

    if memory_str.is_empty() {
        return Err(eyre!("Memory string cannot be empty"));
    }

    // Try to strip unit suffix, checking case-insensitively
    let (number_str, unit) = if let Some(num) = memory_str
        .strip_suffix('G')
        .or_else(|| memory_str.strip_suffix('g'))
    {
        (num, "GiB")
    } else if let Some(num) = memory_str
        .strip_suffix('M')
        .or_else(|| memory_str.strip_suffix('m'))
    {
        (num, "MiB")
    } else if let Some(num) = memory_str
        .strip_suffix('K')
        .or_else(|| memory_str.strip_suffix('k'))
    {
        (num, "KiB")
    } else {
        // No suffix, assume megabytes
        (memory_str, "MiB")
    };

    let number: f64 = number_str
        .parse()
        .context("Invalid number in memory specification")?;

    // Use libvirt helper to get bytes per unit
    let bytes_per_unit = unit_to_bytes(unit).ok_or_else(|| eyre!("Unknown unit: {}", unit))? as f64;

    let mib = 1024.0 * 1024.0;
    let total_mb = (number * bytes_per_unit) / mib;

    Ok(total_mb as u32)
}

/// Generate a unique VM name from an image name
pub fn generate_unique_vm_name(image: &str, existing_domains: &[String]) -> String {
    // Extract image name from full image path
    let base_name = if let Some(last_slash) = image.rfind('/') {
        &image[last_slash + 1..]
    } else {
        image
    };

    // Remove tag if present
    let base_name = if let Some(colon) = base_name.find(':') {
        &base_name[..colon]
    } else {
        base_name
    };

    // Sanitize name (replace invalid characters with hyphens)
    let sanitized: String = base_name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();

    // Find unique name by appending numbers
    let mut candidate = sanitized.clone();
    let mut counter = 1;

    while existing_domains.contains(&candidate) {
        counter += 1;
        candidate = format!("{}-{}", sanitized, counter);
    }

    candidate
}
