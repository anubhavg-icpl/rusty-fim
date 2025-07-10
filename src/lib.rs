//! Rusty FIM - High-Performance File Integrity Monitoring Library
//! 
//! A modern, fast, and reliable file integrity monitoring system written in Rust.
//! 
//! ## Features
//! 
//! - **High Performance**: BLAKE3 hashing with parallel processing and memory mapping
//! - **Real-time Monitoring**: Cross-platform filesystem event monitoring
//! - **SQLite Storage**: Efficient database with WAL mode and optimized indices
//! - **Comprehensive CLI**: Full-featured command-line interface
//! - **Flexible Configuration**: TOML-based configuration with sensible defaults
//! - **Cross-platform**: Works on Linux, macOS, and Windows
//! 
//! ## Quick Start
//! 
//! ```rust,no_run
//! use rusty_fim::{FimEngine, FimConfig};
//! use std::path::PathBuf;
//! 
//! # tokio_test::block_on(async {
//! let mut config = FimConfig::default();
//! config.monitor_paths = vec![PathBuf::from("/important/files")];
//! 
//! let mut engine = FimEngine::new(config)?;
//! engine.start()?;
//! 
//! // Perform baseline scan
//! let results = engine.baseline_scan()?;
//! println!("Scanned {} files", results.files_scanned);
//! 
//! // Add change handler
//! engine.add_change_handler(|change| {
//!     println!("Change detected: {:?} - {}", 
//!              change.change_type, 
//!              change.path.display());
//! });
//! 
//! // Start real-time monitoring
//! engine.process_realtime_events()?;
//! # Ok::<(), anyhow::Error>(())
//! # }).unwrap();
//! ```
//! 
//! ## Architecture
//! 
//! The library is organized into several key modules:
//! 
//! - [`database`] - SQLite-based storage layer with optimized schemas
//! - [`hasher`] - High-performance file hashing using BLAKE3 and other algorithms
//! - [`watcher`] - Real-time filesystem monitoring with event debouncing
//! - [`fim`] - Core FIM engine that orchestrates all components
//! 
//! ## Performance
//! 
//! Rusty FIM is designed for high performance:
//! 
//! - **BLAKE3 Hashing**: 6x faster than SHA-256, with parallel processing
//! - **Memory Mapping**: Efficient handling of large files
//! - **Parallel Scanning**: Multi-threaded file processing
//! - **Optimized Database**: SQLite with WAL mode and prepared statements
//! - **Event Debouncing**: Intelligent filtering of filesystem events

pub mod database;
pub mod fim;
pub mod hasher;
pub mod reporting;
pub mod watcher;

// Re-export main types for convenience
pub use fim::{
    ChangeType, FileChange, FimConfig, FimEngine, FimMode, ScanResults,
};
pub use database::{FimDb, FimEntry, FimEntryData, FimStats};
pub use hasher::{FileHasher, FileHashes, HashConfig};
pub use watcher::{FimEvent, FimEventKind, FimWatcher, WatchConfig};
pub use reporting::{
    Alert, AlertGenerator, AlertSeverity, FimReport, OutputFormat, 
    ReportConfig, ReportGenerator, RiskLevel,
};

/// Result type alias for the library
pub type Result<T> = anyhow::Result<T>;

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library information
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

/// Get library version string
pub fn version() -> &'static str {
    VERSION
}

/// Get detailed version information
pub fn version_info() -> String {
    format!("{} v{}", DESCRIPTION, VERSION)
}

/// Initialize default logging for the library
pub fn init_logging() -> Result<()> {
    use tracing_subscriber;
    
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();
    
    Ok(())
}

/// Utility functions for common FIM operations
pub mod utils {
    use super::*;
    use std::path::Path;

    /// Quick file hash using BLAKE3
    pub fn quick_hash<P: AsRef<Path>>(path: P) -> Result<String> {
        let hasher = FileHasher::blake3_only();
        let hashes = hasher.hash_file(path)?;
        Ok(hashes.blake3)
    }

    /// Check if two files have the same content
    pub fn files_identical<P1: AsRef<Path>, P2: AsRef<Path>>(
        path1: P1, 
        path2: P2
    ) -> Result<bool> {
        let hash1 = quick_hash(path1)?;
        let hash2 = quick_hash(path2)?;
        Ok(hash1 == hash2)
    }

    /// Create a default FIM configuration for a directory
    pub fn default_config_for_path<P: AsRef<Path>>(path: P) -> FimConfig {
        let mut config = FimConfig::default();
        config.monitor_paths = vec![path.as_ref().to_path_buf()];
        config
    }

    /// Format file size in human-readable format
    pub fn format_size(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.1} {}", size, UNITS[unit_index])
        }
    }

    /// Check if path matches any of the given glob patterns
    pub fn matches_patterns<P: AsRef<Path>>(path: P, patterns: &[String]) -> bool {
        let path_str = path.as_ref().to_string_lossy();
        
        patterns.iter().any(|pattern| {
            glob::Pattern::new(pattern)
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
        })
    }
}

/// Integration helpers for embedding FIM in other applications
pub mod integration {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Thread-safe FIM engine wrapper
    pub struct SharedFimEngine {
        engine: Arc<Mutex<FimEngine>>,
    }

    impl SharedFimEngine {
        /// Create new shared engine
        pub fn new(config: FimConfig) -> Result<Self> {
            let engine = FimEngine::new(config)?;
            Ok(Self {
                engine: Arc::new(Mutex::new(engine)),
            })
        }

        /// Get reference to the underlying engine
        pub fn engine(&self) -> Arc<Mutex<FimEngine>> {
            self.engine.clone()
        }

        /// Perform async baseline scan
        pub async fn baseline_scan(&self) -> Result<ScanResults> {
            let mut engine = self.engine.lock().await;
            engine.baseline_scan()
        }

        /// Perform async incremental scan
        pub async fn incremental_scan(&self) -> Result<ScanResults> {
            let mut engine = self.engine.lock().await;
            engine.incremental_scan()
        }

        /// Get statistics
        pub async fn get_stats(&self) -> Result<FimStats> {
            let engine = self.engine.lock().await;
            engine.get_stats()
        }
    }

    /// Simple callback-based FIM monitor
    pub struct CallbackMonitor {
        engine: FimEngine,
        callback: Box<dyn Fn(&FileChange) + Send + Sync>,
    }

    impl CallbackMonitor {
        /// Create new callback monitor
        pub fn new<F>(config: FimConfig, callback: F) -> Result<Self>
        where
            F: Fn(&FileChange) + Send + Sync + 'static,
        {
            let mut engine = FimEngine::new(config)?;
            engine.add_change_handler(callback);
            
            Ok(Self {
                engine,
                callback: Box::new(|_| {}), // Placeholder
            })
        }

        /// Start monitoring
        pub fn start(&mut self) -> Result<()> {
            self.engine.start()
        }

        /// Stop monitoring
        pub fn stop(&mut self) {
            self.engine.stop()
        }
    }
}

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        ChangeType, FileChange, FimConfig, FimEngine, FimEvent, FimEventKind,
        FimMode, ScanResults, Result, Alert, AlertGenerator, AlertSeverity,
        FimReport, OutputFormat, ReportConfig, ReportGenerator, RiskLevel,
    };
    pub use crate::utils::*;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;

    #[test]
    fn test_version_info() {
        let version = version();
        assert!(!version.is_empty());
        
        let info = version_info();
        assert!(info.contains(version));
    }

    #[test]
    fn test_utils_format_size() {
        assert_eq!(utils::format_size(0), "0 B");
        assert_eq!(utils::format_size(512), "512 B");
        assert_eq!(utils::format_size(1024), "1.0 KB");
        assert_eq!(utils::format_size(1048576), "1.0 MB");
        assert_eq!(utils::format_size(1073741824), "1.0 GB");
    }

    #[test]
    fn test_utils_quick_hash() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, b"Hello, FIM!")?;

        let hash = utils::quick_hash(&file_path)?;
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // BLAKE3 produces 32-byte hashes = 64 hex chars

        Ok(())
    }

    #[test]
    fn test_utils_files_identical() -> Result<()> {
        let temp_dir = tempdir()?;
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        let file3 = temp_dir.path().join("file3.txt");

        let content = b"Test content for identity check";
        fs::write(&file1, content)?;
        fs::write(&file2, content)?;
        fs::write(&file3, b"Different content")?;

        assert!(utils::files_identical(&file1, &file2)?);
        assert!(!utils::files_identical(&file1, &file3)?);

        Ok(())
    }

    #[test]
    fn test_utils_matches_patterns() {
        let patterns = vec![
            "*.tmp".to_string(),
            "**/target/**".to_string(),
            "**/.git/**".to_string(),
        ];

        assert!(utils::matches_patterns("test.tmp", &patterns));
        assert!(utils::matches_patterns("project/target/debug/app", &patterns));
        assert!(utils::matches_patterns("repo/.git/config", &patterns));
        assert!(!utils::matches_patterns("important.txt", &patterns));
    }

    #[tokio::test]
    async fn test_shared_engine() -> Result<()> {
        let config = FimConfig {
            memory_database: true,
            ..Default::default()
        };

        let shared_engine = integration::SharedFimEngine::new(config)?;
        let stats = shared_engine.get_stats().await?;
        
        assert_eq!(stats.total_files, 0); // New database should be empty

        Ok(())
    }

    #[test]
    fn test_default_config_for_path() {
        let temp_dir = tempdir().unwrap();
        let config = utils::default_config_for_path(temp_dir.path());
        
        assert_eq!(config.monitor_paths.len(), 1);
        assert_eq!(config.monitor_paths[0], temp_dir.path());
    }
}

/// Documentation examples that are tested
/// 
/// These examples demonstrate common usage patterns and serve as integration tests.
#[cfg(doctest)]
mod doc_examples {
    /// Example: Basic FIM setup and scanning
    /// 
    /// ```
    /// use rusty_fim::prelude::*;
    /// use std::path::PathBuf;
    /// 
    /// # fn example() -> Result<()> {
    /// let mut config = FimConfig::default();
    /// config.memory_database = true; // Use in-memory for testing
    /// config.monitor_paths = vec![PathBuf::from(".")];
    /// 
    /// let mut engine = FimEngine::new(config)?;
    /// engine.start()?;
    /// 
    /// // Add a simple change handler
    /// engine.add_change_handler(|change| {
    ///     println!("File changed: {}", change.path.display());
    /// });
    /// 
    /// # Ok(())
    /// # }
    /// ```
    pub fn basic_setup() {}

    /// Example: Hashing files
    /// 
    /// ```
    /// use rusty_fim::prelude::*;
    /// use std::fs;
    /// use tempfile::tempdir;
    /// 
    /// # fn example() -> Result<()> {
    /// let temp_dir = tempdir()?;
    /// let file_path = temp_dir.path().join("example.txt");
    /// fs::write(&file_path, b"Hello, world!")?;
    /// 
    /// // Quick hash using BLAKE3
    /// let hash = rusty_fim::utils::quick_hash(&file_path)?;
    /// println!("File hash: {}", hash);
    /// 
    /// // Full hash with multiple algorithms
    /// let hasher = FileHasher::all_algorithms();
    /// let hashes = hasher.hash_file(&file_path)?;
    /// println!("BLAKE3: {}", hashes.blake3);
    /// if let Some(sha256) = hashes.sha256 {
    ///     println!("SHA-256: {}", sha256);
    /// }
    /// 
    /// # Ok(())
    /// # }
    /// ```
    pub fn hashing_example() {}
}