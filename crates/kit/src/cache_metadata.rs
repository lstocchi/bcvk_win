//! Cache metadata management for bootc disk images
//!
//! This module provides functionality for storing and retrieving metadata about bootc disk images
//! using extended attributes (xattrs). This enables efficient caching by allowing bcvk to detect
//! when a disk image can be reused instead of regenerating it.
//!
//! The cache system stores two separate xattrs:
//! - A SHA256 hash of all build inputs for cache validation
//! - The container image digest for visibility and tracking

use crate::install_options::InstallOptions;
use cap_std_ext::cap_std::{self, fs::Dir};
use cap_std_ext::dirext::CapStdExtDirExt;
use color_eyre::{eyre::Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;

/// Extended attribute name for storing bootc cache hash
const BOOTC_CACHE_HASH_XATTR: &str = "user.bootc.cache_hash";

/// Extended attribute name for storing container image digest
const BOOTC_IMAGE_DIGEST_XATTR: &str = "user.bootc.image_digest";

/// Build inputs used to generate a cache hash
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheInputs {
    /// SHA256 digest of the source container image
    image_digest: String,

    /// Source image reference (e.g., "quay.io/centos-bootc/centos-bootc:stream9")
    /// This is crucial because it determines the upgrade source for the installed system
    source_imgref: String,

    /// Target transport
    #[serde(skip_serializing_if = "Option::is_none")]
    target_transport: Option<String>,

    /// Filesystem type used for installation (e.g., "ext4", "xfs", "btrfs")
    #[serde(skip_serializing_if = "Option::is_none")]
    filesystem: Option<String>,

    /// Root filesystem size if specified
    #[serde(skip_serializing_if = "Option::is_none")]
    root_size: Option<String>,

    /// Whether to use composefs-native storage
    composefs_backend: bool,

    /// Kernel arguments used during installation
    kernel_args: Vec<String>,

    /// Version of the cache format for future compatibility
    version: u32,
}

/// Metadata stored on disk images for caching purposes
#[derive(Debug, Clone)]
pub struct DiskImageMetadata {
    /// SHA256 digest of the source container image
    pub digest: String,

    /// Source image reference (e.g., "quay.io/centos-bootc/centos-bootc:stream9")
    /// This is crucial because it determines the upgrade source for the installed system
    pub source_imgref: String,

    /// Target transport
    pub target_transport: Option<String>,

    /// Filesystem type used for installation (e.g., "ext4", "xfs", "btrfs")
    pub filesystem: Option<String>,

    /// Root filesystem size if specified
    pub root_size: Option<String>,

    /// Whether to use composefs-native storage
    pub composefs_backend: bool,

    /// Kernel arguments used during installation
    pub kernel_args: Vec<String>,

    /// Version of the metadata format for future compatibility
    pub version: u32,
}

impl DiskImageMetadata {
    /// Generate SHA256 hash of all build inputs
    pub fn compute_cache_hash(&self) -> String {
        let inputs = CacheInputs {
            image_digest: self.digest.clone(),
            source_imgref: self.source_imgref.clone(),
            target_transport: self.target_transport.clone(),
            filesystem: self.filesystem.clone(),
            root_size: self.root_size.clone(),
            composefs_backend: self.composefs_backend,
            kernel_args: self.kernel_args.clone(),
            version: self.version,
        };

        let json = serde_json::to_string(&inputs).expect("Failed to serialize cache inputs");
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    }

    /* /// Write metadata to a file using extended attributes via rustix
    pub fn write_to_file(&self, file: &File) -> Result<()> {
        // Write the cache hash
        let cache_hash = self.compute_cache_hash();
        rustix::fs::fsetxattr(
            file,
            BOOTC_CACHE_HASH_XATTR,
            cache_hash.as_bytes(),
            rustix::fs::XattrFlags::empty(),
        )
        .with_context(|| "Failed to set cache hash xattr")?;

        // Write the image digest separately for visibility
        rustix::fs::fsetxattr(
            file,
            BOOTC_IMAGE_DIGEST_XATTR,
            self.digest.as_bytes(),
            rustix::fs::XattrFlags::empty(),
        )
        .with_context(|| "Failed to set image digest xattr")?;

        tracing::debug!(
            "Wrote cache hash {} and image digest {} to disk image",
            cache_hash,
            self.digest
        );
        Ok(())
    }

    /// Read image digest from a file path using extended attributes
    pub fn read_image_digest_from_path(path: &Path) -> Result<Option<String>> {
        // First check if file exists
        if !path.exists() {
            return Ok(None);
        }

        // Get the parent directory and file name
        // Use current directory if parent is empty (for bare filenames like "disk.img")
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let file_name = path
            .file_name()
            .ok_or_else(|| color_eyre::eyre::eyre!("Path has no file name"))?;

        // Open the parent directory with cap-std
        let dir = Dir::open_ambient_dir(parent, cap_std::ambient_authority())
            .with_context(|| format!("Failed to open directory {:?}", parent))?;

        // Get the image digest xattr
        let digest_data = match dir.getxattr(file_name, OsStr::new(BOOTC_IMAGE_DIGEST_XATTR))? {
            Some(data) => data,
            None => {
                tracing::debug!("No image digest xattr found on {:?}", path);
                return Ok(None);
            }
        };

        let digest = std::str::from_utf8(&digest_data)
            .with_context(|| "Invalid UTF-8 in image digest xattr")?;

        tracing::debug!("Read image digest from {:?}: {}", path, digest);
        Ok(Some(digest.to_string()))
    } */
}

impl DiskImageMetadata {
    /// Create new metadata from InstallOptions, image digest, and source imgref
    pub fn from(options: &InstallOptions, image_digest: &str, source_imgref: &str) -> Self {
        Self {
            version: 1,
            digest: image_digest.to_owned(),
            source_imgref: source_imgref.to_owned(),
            target_transport: options.target_transport.clone(),
            filesystem: options.filesystem.clone(),
            root_size: options.root_size.clone(),
            kernel_args: options.karg.clone(),
            composefs_backend: options.composefs_backend,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ValidationError {
    #[error("file is missing")]
    MissingFile,
    #[error("Missing extended attribute metadata")]
    MissingXattr,
    #[error("Hash mismatch")]
    HashMismatch,
}

/// Check if a cached disk image can be reused by comparing cache hashes
pub fn check_cached_disk(
    path: &Path,
    image_digest: &str,
    source_imgref: &str,
    install_options: &InstallOptions,
) -> Result<Result<(), ValidationError>> {
    if !path.exists() {
        tracing::debug!("Disk image {:?} does not exist", path);
        return Ok(Err(ValidationError::MissingFile));
    }

    // Create metadata for the current request to compute expected hash
    let expected_meta = DiskImageMetadata::from(install_options, image_digest, source_imgref);
    let expected_hash = expected_meta.compute_cache_hash();

    println!("expected_hash: {}", expected_hash);

    // Read the cache hash from the disk image
    let path_str = path.to_str().ok_or_else(|| color_eyre::eyre::eyre!("Path is not valid UTF-8"));
    let mut cached_hash: Vec<u8> = Vec::new();
    if win_ads::get_ads(path_str?, BOOTC_CACHE_HASH_XATTR, &mut cached_hash).is_err() {
        tracing::debug!("No cache hash xattr found on {:?}", path);
        return Ok(Err(ValidationError::MissingXattr));
    }
    // Use current directory if parent is empty (for bare filenames like "disk.img")
    let cached_hash = std::str::from_utf8(&cached_hash)
        .with_context(|| "Invalid UTF-8 in cache hash xattr")?;

    println!("cached_hash: {}", cached_hash);
    let matches = expected_hash == cached_hash;
    if matches {
        tracing::debug!(
            "Found cached disk image at {:?} matching cache hash {}",
            path,
            expected_hash
        );
        Ok(Ok(()))
    } else {
        tracing::debug!(
            "Cached disk at {:?} does not match requirements. \
             Expected hash: {}, found: {}",
            path,
            expected_hash,
            cached_hash
        );
        Ok(Err(ValidationError::HashMismatch))
    }
}