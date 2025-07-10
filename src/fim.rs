//! Core File Integrity Monitoring engine
//! 
//! Coordinates scanning, hashing, database operations, and real-time monitoring
//! to provide comprehensive file integrity monitoring capabilities.

use crate::database::{FimDb, FimEntry, FimEntryData, FimStats};
use crate::hasher::{FileHasher, HashConfig};
use crate::watcher::{FimEvent, FimEventKind, FimWatcher, WatchConfig};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
// use std::collections::HashSet; // unused
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, error, info};

/// Serde module for Duration serialization
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

/// FIM operation modes
#[derive(Debug, Clone, PartialEq)]
pub enum FimMode {
    /// Initial baseline scan
    Baseline,
    /// Incremental scan (check changes since last scan)
    Incremental,
    /// Real-time monitoring
    Realtime,
    /// Verification against existing baseline
    Verify,
}

/// FIM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimConfig {
    /// Paths to monitor
    pub monitor_paths: Vec<PathBuf>,
    /// Exclude patterns
    pub exclude_patterns: Vec<String>,
    /// Hash configuration
    pub hash_config: HashConfig,
    /// Watch configuration
    pub watch_config: WatchConfig,
    /// Database in memory vs disk
    pub memory_database: bool,
    /// Scan performance settings
    pub scan_threads: Option<usize>,
    /// Maximum file size to hash (bytes)
    pub max_file_size: Option<u64>,
    /// Enable real-time monitoring
    pub enable_realtime: bool,
    /// Scan interval for incremental mode (seconds)
    pub scan_interval: u64,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            monitor_paths: vec![],
            exclude_patterns: vec![
                "**/target/**".to_string(),
                "**/.git/**".to_string(),
                "**/node_modules/**".to_string(),
                "**/*.tmp".to_string(),
                "**/*.log".to_string(),
            ],
            hash_config: HashConfig::default(),
            watch_config: WatchConfig::default(),
            memory_database: false,
            scan_threads: None,
            max_file_size: Some(1024 * 1024 * 1024), // 1GB limit
            enable_realtime: true,
            scan_interval: 3600, // 1 hour
        }
    }
}

/// FIM scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub files_scanned: u64,
    pub files_added: u64,
    pub files_modified: u64,
    pub files_deleted: u64,
    pub errors: u64,
    #[serde(with = "duration_serde")]
    pub scan_duration: Duration,
    pub total_size: u64,
}

/// File integrity change types
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
    PermissionChanged,
    SizeChanged,
    HashChanged,
    TimestampChanged,
}

/// File change record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: PathBuf,
    pub change_type: ChangeType,
    pub old_entry: Option<FimEntryData>,
    pub new_entry: Option<FimEntryData>,
    pub detected_at: DateTime<Utc>,
}

/// Core FIM engine
pub struct FimEngine {
    config: FimConfig,
    database: FimDb,
    hasher: FileHasher,
    watcher: Option<FimWatcher>,
    is_running: Arc<Mutex<bool>>,
    change_handlers: Vec<Box<dyn Fn(&FileChange) + Send + Sync>>,
}

impl FimEngine {
    /// Create new FIM engine
    pub fn new(config: FimConfig) -> Result<Self> {
        let database = FimDb::init(config.memory_database)
            .context("Failed to initialize database")?;
        
        let hasher = FileHasher::new(config.hash_config.clone());
        
        let mut watch_config = config.watch_config.clone();
        watch_config.paths = config.monitor_paths.clone();
        
        let watcher = if config.enable_realtime {
            Some(FimWatcher::new(watch_config)?)
        } else {
            None
        };

        Ok(Self {
            config,
            database,
            hasher,
            watcher,
            is_running: Arc::new(Mutex::new(false)),
            change_handlers: Vec::new(),
        })
    }

    /// Add change handler callback
    pub fn add_change_handler<F>(&mut self, handler: F)
    where
        F: Fn(&FileChange) + Send + Sync + 'static,
    {
        self.change_handlers.push(Box::new(handler));
    }

    /// Start the FIM engine
    pub fn start(&mut self) -> Result<()> {
        *self.is_running.lock().unwrap() = true;
        
        info!("Starting FIM engine");
        
        // Start real-time watcher if enabled
        if let Some(ref mut watcher) = self.watcher {
            watcher.start().context("Failed to start filesystem watcher")?;
            info!("Real-time monitoring enabled");
        }

        Ok(())
    }

    /// Stop the FIM engine
    pub fn stop(&mut self) {
        *self.is_running.lock().unwrap() = false;
        
        if let Some(ref mut watcher) = self.watcher {
            watcher.stop();
        }
        
        info!("FIM engine stopped");
    }

    /// Perform baseline scan
    pub fn baseline_scan(&mut self) -> Result<ScanResults> {
        info!("Starting baseline scan");
        let start_time = Instant::now();
        
        // Clear existing data
        self.database.set_all_unscanned()?;
        
        let mut results = ScanResults {
            files_scanned: 0,
            files_added: 0,
            files_modified: 0,
            files_deleted: 0,
            errors: 0,
            scan_duration: Duration::default(),
            total_size: 0,
        };

        // Collect all files to scan
        let files_to_scan = self.collect_files_to_scan()?;
        info!("Found {} files to scan", files_to_scan.len());

        // Configure parallelism
        let thread_count = self.config.scan_threads
            .unwrap_or_else(|| num_cpus::get());
        rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build_global()
            .context("Failed to configure thread pool")?;

        // Begin database transaction for batch operations
        self.database.begin_transaction()?;

        let start_scan = Instant::now();
        
        // Process files sequentially (SQLite is not thread-safe)
        let scan_results: Vec<_> = files_to_scan
            .iter()
            .map(|path| self.scan_single_file(path))
            .collect();

        // Process results and update database
        for scan_result in scan_results {
            match scan_result {
                Ok((entry_data, file_size)) => {
                    results.files_scanned += 1;
                    results.total_size += file_size;
                    results.files_added += 1;
                    
                    // Insert into database
                    if let Err(e) = self.database.insert_data(&entry_data.path, &entry_data.data) {
                        error!("Failed to insert file data: {}", e);
                        results.errors += 1;
                    }
                }
                Err(e) => {
                    error!("Scan error: {}", e);
                    results.errors += 1;
                }
            }

            // Periodic commit for large scans
            if results.files_scanned % 1000 == 0 {
                self.database.force_commit();
                debug!("Processed {} files", results.files_scanned);
            }
        }

        // Final commit
        self.database.commit_transaction()?;
        
        // Clean up unscanned entries
        let deleted = self.database.delete_not_scanned()?;
        results.files_deleted = deleted as u64;

        results.scan_duration = start_scan.elapsed();
        
        info!(
            "Baseline scan completed: {} files scanned, {} added, {} errors in {:?}",
            results.files_scanned,
            results.files_added,
            results.errors,
            results.scan_duration
        );

        Ok(results)
    }

    /// Perform incremental scan
    pub fn incremental_scan(&mut self) -> Result<ScanResults> {
        info!("Starting incremental scan");
        let start_time = Instant::now();
        
        // Mark all entries as unscanned
        self.database.set_all_unscanned()?;
        
        let mut results = ScanResults {
            files_scanned: 0,
            files_added: 0,
            files_modified: 0,
            files_deleted: 0,
            errors: 0,
            scan_duration: Duration::default(),
            total_size: 0,
        };

        let files_to_scan = self.collect_files_to_scan()?;
        
        self.database.begin_transaction()?;

        // Process each file and check for changes
        for file_path in files_to_scan {
            match self.check_file_changes(&file_path) {
                Ok(change) => {
                    results.files_scanned += 1;
                    
                    if let Some(change) = change {
                        self.handle_file_change(&change);
                        
                        match change.change_type {
                            ChangeType::Added => results.files_added += 1,
                            ChangeType::Modified | 
                            ChangeType::HashChanged |
                            ChangeType::PermissionChanged |
                            ChangeType::SizeChanged |
                            ChangeType::TimestampChanged => results.files_modified += 1,
                            ChangeType::Deleted => results.files_deleted += 1,
                        }
                    }
                }
                Err(e) => {
                    error!("Error checking file {}: {}", file_path.display(), e);
                    results.errors += 1;
                }
            }

            if results.files_scanned % 1000 == 0 {
                self.database.force_commit();
            }
        }

        // Handle deleted files
        let deleted = self.database.delete_not_scanned()?;
        results.files_deleted += deleted as u64;

        self.database.commit_transaction()?;
        results.scan_duration = start_time.elapsed();

        info!(
            "Incremental scan completed: {} scanned, {} added, {} modified, {} deleted",
            results.files_scanned,
            results.files_added,
            results.files_modified,
            results.files_deleted
        );

        Ok(results)
    }

    /// Process real-time events
    pub fn process_realtime_events(&mut self) -> Result<()> {
        if self.watcher.is_none() {
            return Err(anyhow::anyhow!("Real-time monitoring not enabled"));
        }

        while *self.is_running.lock().unwrap() {
            // Get event from watcher
            let event = if let Some(watcher) = self.watcher.as_ref() {
                watcher.try_next_event()
            } else {
                None
            };
            
            // Handle event if present
            if let Some(event) = event {
                if let Err(e) = self.handle_realtime_event(event) {
                    error!("Error handling real-time event: {}", e);
                }
            }
            
            std::thread::sleep(Duration::from_millis(10));
        }

        Ok(())
    }

    /// Handle real-time filesystem event
    fn handle_realtime_event(&mut self, event: FimEvent) -> Result<()> {
        debug!("Processing real-time event: {:?}", event);

        if self.should_ignore_path(&event.path) {
            return Ok(());
        }

        let change = match event.kind {
            FimEventKind::Created => {
                if let Ok((entry, _)) = self.scan_single_file(&event.path) {
                    self.database.insert_data(&event.path, &entry.data)?;
                    Some(FileChange {
                        path: event.path,
                        change_type: ChangeType::Added,
                        old_entry: None,
                        new_entry: Some(entry.data),
                        detected_at: event.timestamp,
                    })
                } else {
                    None
                }
            }
            FimEventKind::Modified => {
                self.check_file_changes(&event.path)?
            }
            FimEventKind::Deleted => {
                let old_entry = self.database.get_path(&event.path)?;
                self.database.remove_path(&event.path)?;
                
                if let Some(old) = old_entry {
                    Some(FileChange {
                        path: event.path,
                        change_type: ChangeType::Deleted,
                        old_entry: Some(old.data),
                        new_entry: None,
                        detected_at: event.timestamp,
                    })
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(change) = change {
            self.handle_file_change(&change);
        }

        Ok(())
    }

    /// Scan a single file and return entry data
    fn scan_single_file(&self, path: &Path) -> Result<(FimEntry, u64)> {
        let metadata = fs::metadata(path)
            .with_context(|| format!("Failed to get metadata for {}", path.display()))?;

        // Check file size limit
        if let Some(max_size) = self.config.max_file_size {
            if metadata.len() > max_size {
                return Err(anyhow::anyhow!(
                    "File {} exceeds size limit ({} > {})",
                    path.display(),
                    metadata.len(),
                    max_size
                ));
            }
        }

        // Get file times
        let mtime = metadata.modified()
            .map(|t| DateTime::from(t))
            .unwrap_or_else(|_| Utc::now());
        
        let ctime = metadata.created()
            .map(|t| DateTime::from(t))
            .unwrap_or_else(|_| Utc::now());

        // Hash the file
        let hashes = self.hasher.hash_file(path)
            .with_context(|| format!("Failed to hash file {}", path.display()))?;

        // Get file permissions and ownership (Unix-specific)
        #[cfg(unix)]
        let (uid, gid, perm) = {
            use std::os::unix::fs::MetadataExt;
            (
                metadata.uid(),
                metadata.gid(),
                format!("{:o}", metadata.mode() & 0o777),
            )
        };

        #[cfg(not(unix))]
        let (uid, gid, perm) = (0, 0, "644".to_string());

        let entry_data = FimEntryData {
            size: metadata.len(),
            perm,
            uid,
            gid,
            md5: hashes.md5,
            sha1: hashes.sha1,
            sha256: hashes.sha256,
            blake3: hashes.blake3,
            mtime,
            ctime,
            atime: Utc::now(), // Access time is now
            inode: {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    metadata.ino()
                }
                #[cfg(not(unix))]
                0
            },
            dev: {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    metadata.dev()
                }
                #[cfg(not(unix))]
                0
            },
            scanned: true,
        };

        Ok((FimEntry {
            path: path.to_path_buf(),
            data: entry_data,
        }, metadata.len()))
    }

    /// Check for changes in a file
    fn check_file_changes(&mut self, path: &Path) -> Result<Option<FileChange>> {
        if !path.exists() {
            // File was deleted
            if let Some(old_entry) = self.database.get_path(path)? {
                self.database.remove_path(path)?;
                return Ok(Some(FileChange {
                    path: path.to_path_buf(),
                    change_type: ChangeType::Deleted,
                    old_entry: Some(old_entry.data),
                    new_entry: None,
                    detected_at: Utc::now(),
                }));
            }
            return Ok(None);
        }

        let old_entry = self.database.get_path(path)?;
        let (new_entry, _) = self.scan_single_file(path)?;

        // Update database
        self.database.insert_data(path, &new_entry.data)?;

        match old_entry {
            Some(old) => {
                // File existed, check for changes
                let change_type = self.detect_change_type(&old.data, &new_entry.data);
                
                if let Some(change_type) = change_type {
                    Ok(Some(FileChange {
                        path: path.to_path_buf(),
                        change_type,
                        old_entry: Some(old.data),
                        new_entry: Some(new_entry.data),
                        detected_at: Utc::now(),
                    }))
                } else {
                    Ok(None) // No changes
                }
            }
            None => {
                // New file
                Ok(Some(FileChange {
                    path: path.to_path_buf(),
                    change_type: ChangeType::Added,
                    old_entry: None,
                    new_entry: Some(new_entry.data),
                    detected_at: Utc::now(),
                }))
            }
        }
    }

    /// Detect the type of change between old and new entries
    fn detect_change_type(&self, old: &FimEntryData, new: &FimEntryData) -> Option<ChangeType> {
        if old.blake3 != new.blake3 {
            Some(ChangeType::HashChanged)
        } else if old.size != new.size {
            Some(ChangeType::SizeChanged)
        } else if old.perm != new.perm || old.uid != new.uid || old.gid != new.gid {
            Some(ChangeType::PermissionChanged)
        } else if old.mtime != new.mtime || old.ctime != new.ctime {
            Some(ChangeType::TimestampChanged)
        } else {
            None // No significant changes
        }
    }

    /// Handle detected file change
    fn handle_file_change(&self, change: &FileChange) {
        info!("File change detected: {:?} - {}", change.change_type, change.path.display());
        
        // Notify all registered handlers
        for handler in &self.change_handlers {
            handler(change);
        }
    }

    /// Collect all files to scan based on configuration
    fn collect_files_to_scan(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        
        for monitor_path in &self.config.monitor_paths {
            self.collect_files_recursive(monitor_path, &mut files)?;
        }
        
        // Remove duplicates and sort
        files.sort();
        files.dedup();
        
        Ok(files)
    }

    /// Recursively collect files from a directory
    fn collect_files_recursive(&self, path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        if self.should_ignore_path(path) {
            return Ok(());
        }

        if path.is_file() {
            files.push(path.to_path_buf());
        } else if path.is_dir() {
            let entries = fs::read_dir(path)
                .with_context(|| format!("Failed to read directory {}", path.display()))?;

            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_file() {
                    if !self.should_ignore_path(&path) {
                        files.push(path);
                    }
                } else if path.is_dir() {
                    self.collect_files_recursive(&path, files)?;
                }
            }
        }

        Ok(())
    }

    /// Check if path should be ignored
    fn should_ignore_path(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        
        for pattern in &self.config.exclude_patterns {
            if glob::Pattern::new(pattern)
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
            {
                return true;
            }
        }
        
        false
    }

    /// Get FIM statistics
    pub fn get_stats(&self) -> Result<FimStats> {
        self.database.get_stats()
    }

    /// Verify database integrity
    pub fn verify_integrity(&self) -> Result<String> {
        self.database.get_data_checksum()
    }

    /// Export database to JSON
    pub fn export_database(&self, output_path: &Path) -> Result<()> {
        // Implementation would export the database contents
        // This is a placeholder for the actual implementation
        info!("Exporting database to {}", output_path.display());
        Ok(())
    }
}

impl Drop for FimEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, NamedTempFile};
    use std::io::Write;

    #[test]
    fn test_fim_config_default() {
        let config = FimConfig::default();
        assert!(!config.memory_database);
        assert!(config.enable_realtime);
        assert_eq!(config.scan_interval, 3600);
    }

    #[test]
    fn test_scan_single_file() -> Result<()> {
        let config = FimConfig {
            memory_database: true,
            ..Default::default()
        };
        
        let engine = FimEngine::new(config)?;
        
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "Test file content")?;
        
        let (entry, size) = engine.scan_single_file(temp_file.path())?;
        
        assert_eq!(entry.path, temp_file.path());
        assert!(size > 0);
        assert!(!entry.data.blake3.is_empty());
        
        Ok(())
    }

    #[test]
    fn test_change_detection() -> Result<()> {
        let old_data = FimEntryData {
            size: 100,
            perm: "644".to_string(),
            uid: 1000,
            gid: 1000,
            md5: None,
            sha1: None,
            sha256: None,
            blake3: "old_hash".to_string(),
            mtime: Utc::now(),
            ctime: Utc::now(),
            atime: Utc::now(),
            inode: 123,
            dev: 456,
            scanned: true,
        };

        let mut new_data = old_data.clone();
        new_data.blake3 = "new_hash".to_string();

        let config = FimConfig {
            memory_database: true,
            ..Default::default()
        };
        
        let engine = FimEngine::new(config)?;
        
        let change_type = engine.detect_change_type(&old_data, &new_data);
        assert_eq!(change_type, Some(ChangeType::HashChanged));
        
        Ok(())
    }
}