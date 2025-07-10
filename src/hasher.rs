//! High-performance file hashing module for FIM
//! 
//! Provides optimized hashing using BLAKE3 as primary hash with optional
//! legacy algorithm support (SHA-256, SHA-1, MD5) for compatibility.

use anyhow::{Context, Result};
use blake3::Hasher as Blake3Hasher;
use memmap2::Mmap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use tracing::debug;

/// File hash container supporting multiple algorithms
#[derive(Debug, Clone)]
pub struct FileHashes {
    pub blake3: String,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
}

/// Hashing configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashConfig {
    pub use_blake3: bool,
    pub use_sha256: bool,
    pub use_sha1: bool,
    pub use_md5: bool,
    pub use_mmap: bool,
    pub parallel_threshold: u64, // Minimum file size for parallel hashing
}

impl Default for HashConfig {
    fn default() -> Self {
        Self {
            use_blake3: true,
            use_sha256: false,
            use_sha1: false,
            use_md5: false,
            use_mmap: true,
            parallel_threshold: 1024 * 1024, // 1MB
        }
    }
}

/// High-performance file hasher
pub struct FileHasher {
    config: HashConfig,
}

impl FileHasher {
    /// Create new hasher with configuration
    pub fn new(config: HashConfig) -> Self {
        Self { config }
    }

    /// Create hasher with BLAKE3 only (fastest configuration)
    pub fn blake3_only() -> Self {
        Self::new(HashConfig::default())
    }

    /// Create hasher with all algorithms for compatibility
    pub fn all_algorithms() -> Self {
        Self::new(HashConfig {
            use_blake3: true,
            use_sha256: true,
            use_sha1: true,
            use_md5: true,
            use_mmap: true,
            parallel_threshold: 1024 * 1024,
        })
    }

    /// Hash a file using the configured algorithms
    pub fn hash_file<P: AsRef<Path>>(&self, path: P) -> Result<FileHashes> {
        let path = path.as_ref();
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to get metadata for {}", path.display()))?;
        
        let file_size = metadata.len();
        
        // Choose hashing strategy based on file size and configuration
        if self.config.use_mmap && file_size > 0 {
            self.hash_file_mmap(path, file_size)
        } else {
            self.hash_file_buffered(path)
        }
    }

    /// Hash file using memory mapping (fastest for large files)
    fn hash_file_mmap(&self, path: &Path, file_size: u64) -> Result<FileHashes> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open file {}", path.display()))?;
        
        if file_size == 0 {
            return self.hash_empty_file();
        }

        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("Failed to memory map file {}", path.display()))?;

        // Use parallel hashing for large files
        if file_size >= self.config.parallel_threshold && self.config.use_blake3 {
            self.hash_data_parallel(&mmap)
        } else {
            self.hash_data_sequential(&mmap)
        }
    }

    /// Hash file using buffered reading (safer for special files)
    fn hash_file_buffered(&self, path: &Path) -> Result<FileHashes> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open file {}", path.display()))?;
        
        let mut reader = BufReader::new(file);
        let mut buffer = vec![0u8; 64 * 1024]; // 64KB buffer
        
        let mut blake3_hasher = if self.config.use_blake3 {
            Some(Blake3Hasher::new())
        } else {
            None
        };
        
        let mut sha256_hasher = if self.config.use_sha256 {
            Some(Sha256::new())
        } else {
            None
        };

        loop {
            let bytes_read = reader.read(&mut buffer)
                .context("Failed to read file data")?;
            
            if bytes_read == 0 {
                break;
            }
            
            let data = &buffer[..bytes_read];
            
            if let Some(ref mut hasher) = blake3_hasher {
                hasher.update(data);
            }
            
            if let Some(ref mut hasher) = sha256_hasher {
                hasher.update(data);
            }
        }

        Ok(FileHashes {
            blake3: blake3_hasher
                .map(|h| h.finalize().to_hex().to_string())
                .unwrap_or_default(),
            sha256: sha256_hasher
                .map(|h| format!("{:x}", h.finalize())),
            sha1: None, // Implement if needed
            md5: None,  // Implement if needed
        })
    }

    /// Hash data using parallel BLAKE3 (fastest method)
    fn hash_data_parallel(&self, data: &[u8]) -> Result<FileHashes> {
        debug!("Using parallel BLAKE3 hashing for {} bytes", data.len());
        
        let blake3 = if self.config.use_blake3 {
            // BLAKE3 supports parallel hashing natively via Rayon
            let mut hasher = Blake3Hasher::new();
            hasher.update_rayon(data);
            Some(hasher.finalize().to_hex().to_string())
        } else {
            None
        };

        // For other algorithms, we could implement chunked parallel processing
        // but they don't benefit as much from parallelization
        let sha256 = if self.config.use_sha256 {
            Some(format!("{:x}", Sha256::digest(data)))
        } else {
            None
        };

        Ok(FileHashes {
            blake3: blake3.unwrap_or_default(),
            sha256,
            sha1: None,
            md5: None,
        })
    }

    /// Hash data sequentially
    fn hash_data_sequential(&self, data: &[u8]) -> Result<FileHashes> {
        let blake3 = if self.config.use_blake3 {
            Some(blake3::hash(data).to_hex().to_string())
        } else {
            None
        };

        let sha256 = if self.config.use_sha256 {
            Some(format!("{:x}", Sha256::digest(data)))
        } else {
            None
        };

        Ok(FileHashes {
            blake3: blake3.unwrap_or_default(),
            sha256,
            sha1: None,
            md5: None,
        })
    }

    /// Handle empty files
    fn hash_empty_file(&self) -> Result<FileHashes> {
        Ok(FileHashes {
            blake3: if self.config.use_blake3 {
                blake3::hash(b"").to_hex().to_string()
            } else {
                String::new()
            },
            sha256: if self.config.use_sha256 {
                Some(format!("{:x}", Sha256::digest(b"")))
            } else {
                None
            },
            sha1: None,
            md5: None,
        })
    }

    /// Verify file integrity against known hash
    pub fn verify_file<P: AsRef<Path>>(&self, path: P, expected_hash: &str) -> Result<bool> {
        let hashes = self.hash_file(path)?;
        Ok(hashes.blake3 == expected_hash)
    }

    /// Batch hash multiple files in parallel
    pub fn hash_files_parallel<P: AsRef<Path>>(&self, paths: &[P]) -> Vec<Result<FileHashes>> {
        paths.par_iter()
            .map(|path| self.hash_file(path))
            .collect()
    }
}

/// Specialized hasher for checksum verification
pub struct ChecksumVerifier {
    hasher: FileHasher,
}

impl ChecksumVerifier {
    pub fn new() -> Self {
        Self {
            hasher: FileHasher::blake3_only(),
        }
    }

    /// Quick integrity check using BLAKE3
    pub fn quick_check<P: AsRef<Path>>(&self, path: P, expected: &str) -> Result<bool> {
        self.hasher.verify_file(path, expected)
    }

    /// Batch verify multiple files
    pub fn batch_verify<P: AsRef<Path>>(&self, files: &[(P, &str)]) -> Vec<Result<bool>> {
        files.par_iter()
            .map(|(path, expected)| self.hasher.verify_file(path, expected))
            .collect()
    }
}

/// Utility functions for hash operations
pub mod utils {
    use super::*;

    /// Calculate directory checksum (recursive hash of all files)
    pub fn directory_checksum<P: AsRef<Path>>(dir_path: P) -> Result<String> {
        let hasher = FileHasher::blake3_only();
        let mut combined_hasher = Blake3Hasher::new();
        
        let entries: Result<Vec<_>> = std::fs::read_dir(dir_path.as_ref())?
            .collect();
        
        let mut entries = entries?;
        entries.sort_by(|a, b| a.path().cmp(&b.path()));
        
        for entry in entries {
            let path = entry.path();
            if path.is_file() {
                let file_hash = hasher.hash_file(&path)?;
                combined_hasher.update(path.to_string_lossy().as_bytes());
                combined_hasher.update(file_hash.blake3.as_bytes());
            }
        }
        
        Ok(combined_hasher.finalize().to_hex().to_string())
    }

    /// Compare two hash sets for changes
    pub fn compare_hashes(old: &FileHashes, new: &FileHashes) -> bool {
        old.blake3 == new.blake3
    }

    /// Convert hash to short display format
    pub fn short_hash(hash: &str, length: usize) -> String {
        if hash.len() > length {
            format!("{}...", &hash[..length])
        } else {
            hash.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn test_empty_file_hash() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        
        let hasher = FileHasher::blake3_only();
        let hashes = hasher.hash_file(temp_file.path())?;
        
        // BLAKE3 hash of empty string
        assert_eq!(hashes.blake3, blake3::hash(b"").to_hex().to_string());
        Ok(())
    }

    #[test]
    fn test_small_file_hash() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        let test_data = b"Hello, FIM!";
        temp_file.write_all(test_data)?;
        
        let hasher = FileHasher::blake3_only();
        let hashes = hasher.hash_file(temp_file.path())?;
        
        let expected = blake3::hash(test_data).to_hex().to_string();
        assert_eq!(hashes.blake3, expected);
        Ok(())
    }

    #[test]
    fn test_hash_verification() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        let test_data = b"Test data for verification";
        temp_file.write_all(test_data)?;
        
        let hasher = FileHasher::blake3_only();
        let expected = blake3::hash(test_data).to_hex().to_string();
        
        assert!(hasher.verify_file(temp_file.path(), &expected)?);
        assert!(!hasher.verify_file(temp_file.path(), "wrong_hash")?);
        Ok(())
    }

    #[test]
    fn test_directory_checksum() -> Result<()> {
        let temp_dir = tempdir()?;
        
        // Create test files
        let file1_path = temp_dir.path().join("file1.txt");
        let file2_path = temp_dir.path().join("file2.txt");
        
        std::fs::write(&file1_path, b"Content 1")?;
        std::fs::write(&file2_path, b"Content 2")?;
        
        let checksum1 = utils::directory_checksum(temp_dir.path())?;
        
        // Checksum should be deterministic
        let checksum2 = utils::directory_checksum(temp_dir.path())?;
        assert_eq!(checksum1, checksum2);
        
        // Modifying a file should change the checksum
        std::fs::write(&file1_path, b"Modified content")?;
        let checksum3 = utils::directory_checksum(temp_dir.path())?;
        assert_ne!(checksum1, checksum3);
        
        Ok(())
    }

    #[test]
    fn test_parallel_hashing() -> Result<()> {
        let temp_files: Result<Vec<_>> = (0..5)
            .map(|i| {
                let mut temp_file = NamedTempFile::new()?;
                write!(temp_file, "Test data {}", i)?;
                Ok(temp_file)
            })
            .collect();
        
        let temp_files = temp_files?;
        let paths: Vec<_> = temp_files.iter().map(|f| f.path()).collect();
        
        let hasher = FileHasher::blake3_only();
        let results = hasher.hash_files_parallel(&paths);
        
        assert_eq!(results.len(), 5);
        for result in results {
            assert!(result.is_ok());
        }
        
        Ok(())
    }
}