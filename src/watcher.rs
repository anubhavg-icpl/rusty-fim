//! Real-time filesystem monitoring for FIM
//! 
//! Provides cross-platform file system event monitoring using notify with
//! debouncing and intelligent event filtering.

use anyhow::{Context, Result};
use crossbeam_channel::{unbounded, Receiver, Sender};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use notify_debouncer_full::{
    new_debouncer, DebounceEventResult, DebouncedEvent, Debouncer, FileIdMap,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// File system event types for FIM
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FimEventKind {
    Created,
    Modified,
    Deleted,
    MovedFrom(PathBuf),
    MovedTo(PathBuf),
    AttributeChanged,
    Unknown,
}

/// FIM-specific file system event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimEvent {
    pub kind: FimEventKind,
    pub path: PathBuf,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub size: Option<u64>,
    pub is_directory: bool,
}

/// Watch configuration
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Paths to monitor
    pub paths: Vec<PathBuf>,
    /// File patterns to ignore (e.g., "*.tmp", "*.log")
    pub ignore_patterns: Vec<String>,
    /// Extensions to ignore
    pub ignore_extensions: Vec<String>,
    /// Directories to ignore
    pub ignore_directories: Vec<String>,
    /// Debounce timeout for rapid file changes
    pub debounce_timeout: Duration,
    /// Whether to monitor subdirectories recursively
    pub recursive: bool,
    /// Maximum events per second before throttling
    pub max_events_per_second: u32,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            paths: vec![],
            ignore_patterns: vec![
                "*.tmp".to_string(),
                "*.swp".to_string(),
                "*.lock".to_string(),
                "*~".to_string(),
                ".DS_Store".to_string(),
            ],
            ignore_extensions: vec![
                "log".to_string(),
                "cache".to_string(),
                "pid".to_string(),
            ],
            ignore_directories: vec![
                ".git".to_string(),
                ".svn".to_string(),
                "node_modules".to_string(),
                "__pycache__".to_string(),
                ".pytest_cache".to_string(),
                "target".to_string(), // Rust build directory
            ],
            debounce_timeout: Duration::from_millis(250),
            recursive: true,
            max_events_per_second: 1000,
        }
    }
}

/// High-level filesystem watcher for FIM
pub struct FimWatcher {
    config: WatchConfig,
    event_sender: Sender<FimEvent>,
    event_receiver: Receiver<FimEvent>,
    _debouncer: Option<Debouncer<RecommendedWatcher, FileIdMap>>,
    is_running: Arc<Mutex<bool>>,
    event_counter: Arc<Mutex<EventCounter>>,
}

#[derive(Debug)]
struct EventCounter {
    count: u32,
    last_reset: std::time::Instant,
}

impl EventCounter {
    fn new() -> Self {
        Self {
            count: 0,
            last_reset: std::time::Instant::now(),
        }
    }

    fn should_throttle(&mut self, max_per_second: u32) -> bool {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_reset) >= Duration::from_secs(1) {
            self.count = 0;
            self.last_reset = now;
        }
        
        self.count += 1;
        self.count > max_per_second
    }
}

impl FimWatcher {
    /// Create new filesystem watcher
    pub fn new(config: WatchConfig) -> Result<Self> {
        let (event_sender, event_receiver) = unbounded();
        
        Ok(Self {
            config,
            event_sender,
            event_receiver,
            _debouncer: None,
            is_running: Arc::new(Mutex::new(false)),
            event_counter: Arc::new(Mutex::new(EventCounter::new())),
        })
    }

    /// Start monitoring the configured paths
    pub fn start(&mut self) -> Result<()> {
        if *self.is_running.lock().unwrap() {
            warn!("Watcher is already running");
            return Ok(());
        }

        info!("Starting FIM watcher for {} paths", self.config.paths.len());
        
        let event_sender = self.event_sender.clone();
        let config = self.config.clone();
        let is_running = self.is_running.clone();
        let event_counter = self.event_counter.clone();

        let (tx, rx) = unbounded();

        // Create debounced watcher
        let mut debouncer = new_debouncer(
            config.debounce_timeout,
            None,
            move |result: DebounceEventResult| {
                if let Err(e) = tx.send(result) {
                    error!("Failed to send debounced event: {}", e);
                }
            },
        )?;

        // Watch all configured paths
        for path in &self.config.paths {
            let mode = if self.config.recursive {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            };

            debouncer
                .watcher()
                .watch(path, mode)
                .with_context(|| format!("Failed to watch path: {}", path.display()))?;
            
            info!("Watching path: {} (recursive: {})", path.display(), self.config.recursive);
        }

        // Start event processing thread
        let _handle = thread::spawn(move || {
            *is_running.lock().unwrap() = true;
            
            while *is_running.lock().unwrap() {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(result) => {
                        if let Err(e) = Self::handle_debounced_events(
                            result,
                            &event_sender,
                            &config,
                            &event_counter,
                        ) {
                            error!("Error handling events: {}", e);
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        // Normal timeout, continue
                        continue;
                    }
                    Err(e) => {
                        error!("Error receiving events: {}", e);
                        break;
                    }
                }
            }
        });

        self._debouncer = Some(debouncer);
        *self.is_running.lock().unwrap() = true;

        Ok(())
    }

    /// Stop the watcher
    pub fn stop(&mut self) {
        *self.is_running.lock().unwrap() = false;
        self._debouncer = None;
        info!("FIM watcher stopped");
    }

    /// Get next FIM event (blocking)
    pub fn next_event(&self) -> Result<FimEvent> {
        self.event_receiver
            .recv()
            .context("Failed to receive event")
    }

    /// Try to get next FIM event (non-blocking)
    pub fn try_next_event(&self) -> Option<FimEvent> {
        self.event_receiver.try_recv().ok()
    }

    /// Get event receiver for custom processing
    pub fn event_receiver(&self) -> &Receiver<FimEvent> {
        &self.event_receiver
    }

    /// Handle debounced events from notify
    fn handle_debounced_events(
        result: DebounceEventResult,
        sender: &Sender<FimEvent>,
        config: &WatchConfig,
        event_counter: &Arc<Mutex<EventCounter>>,
    ) -> Result<()> {
        match result {
            Ok(events) => {
                for event in events {
                    // Check throttling
                    {
                        let mut counter = event_counter.lock().unwrap();
                        if counter.should_throttle(config.max_events_per_second) {
                            warn!("Event rate too high, throttling");
                            continue;
                        }
                    }

                    if let Some(fim_event) = Self::convert_event(event, config) {
                        if let Err(e) = sender.send(fim_event) {
                            error!("Failed to send FIM event: {}", e);
                        }
                    }
                }
            }
            Err(errors) => {
                for error in errors {
                    error!("Filesystem watch error: {}", error);
                }
            }
        }
        Ok(())
    }

    /// Convert notify event to FIM event
    fn convert_event(event: DebouncedEvent, config: &WatchConfig) -> Option<FimEvent> {
        // Get the first path from the event
        let path = event.event.paths.first()?;
        
        // Apply ignore filters
        if Self::should_ignore_path(path, config) {
            debug!("Ignoring path: {}", path.display());
            return None;
        }

        let is_directory = path.is_dir();
        let size = if !is_directory {
            std::fs::metadata(path).ok().map(|m| m.len())
        } else {
            None
        };

        let kind = match event.event.kind {
            EventKind::Create(_) => FimEventKind::Created,
            EventKind::Modify(_) => FimEventKind::Modified,
            EventKind::Remove(_) => FimEventKind::Deleted,
            EventKind::Access(_) => {
                // Only track access if it's metadata change
                FimEventKind::AttributeChanged
            }
            _ => FimEventKind::Unknown,
        };

        Some(FimEvent {
            kind,
            path: path.clone(),
            timestamp: chrono::Utc::now(),
            size,
            is_directory,
        })
    }

    /// Check if path should be ignored based on configuration
    fn should_ignore_path(path: &Path, config: &WatchConfig) -> bool {
        let filename = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
        
        // Check ignore patterns
        for pattern in &config.ignore_patterns {
            if Self::matches_pattern(&filename, pattern) {
                return true;
            }
        }

        // Check extensions
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy();
            if config.ignore_extensions.contains(&ext_str.to_string()) {
                return true;
            }
        }

        // Check directory names
        for component in path.components() {
            let component_str = component.as_os_str().to_string_lossy();
            if config.ignore_directories.contains(&component_str.to_string()) {
                return true;
            }
        }

        false
    }

    /// Simple glob pattern matching
    fn matches_pattern(name: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        
        if pattern.starts_with('*') && pattern.len() > 1 {
            let suffix = &pattern[1..];
            return name.ends_with(suffix);
        }
        
        if pattern.ends_with('*') && pattern.len() > 1 {
            let prefix = &pattern[..pattern.len() - 1];
            return name.starts_with(prefix);
        }
        
        name == pattern
    }

    /// Get statistics about the watcher
    pub fn get_stats(&self) -> WatcherStats {
        let counter = self.event_counter.lock().unwrap();
        WatcherStats {
            is_running: *self.is_running.lock().unwrap(),
            events_processed: counter.count,
            paths_watched: self.config.paths.len(),
        }
    }
}

/// Watcher statistics
#[derive(Debug, Clone)]
pub struct WatcherStats {
    pub is_running: bool,
    pub events_processed: u32,
    pub paths_watched: usize,
}

impl Drop for FimWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Batch event processor for efficient handling
pub struct EventBatcher {
    events: Vec<FimEvent>,
    max_batch_size: usize,
    timeout: Duration,
    last_flush: std::time::Instant,
}

impl EventBatcher {
    pub fn new(max_batch_size: usize, timeout: Duration) -> Self {
        Self {
            events: Vec::with_capacity(max_batch_size),
            max_batch_size,
            timeout,
            last_flush: std::time::Instant::now(),
        }
    }

    /// Add event to batch
    pub fn add_event(&mut self, event: FimEvent) -> Option<Vec<FimEvent>> {
        self.events.push(event);
        
        if self.should_flush() {
            self.flush()
        } else {
            None
        }
    }

    /// Check if batch should be flushed
    fn should_flush(&self) -> bool {
        self.events.len() >= self.max_batch_size
            || self.last_flush.elapsed() >= self.timeout
    }

    /// Flush current batch
    pub fn flush(&mut self) -> Option<Vec<FimEvent>> {
        if self.events.is_empty() {
            return None;
        }

        let events = std::mem::take(&mut self.events);
        self.last_flush = std::time::Instant::now();
        Some(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_watch_config_default() {
        let config = WatchConfig::default();
        assert!(config.recursive);
        assert!(config.ignore_patterns.contains(&"*.tmp".to_string()));
        assert_eq!(config.debounce_timeout, Duration::from_millis(250));
    }

    #[test]
    fn test_pattern_matching() {
        assert!(FimWatcher::matches_pattern("test.tmp", "*.tmp"));
        assert!(FimWatcher::matches_pattern("backup.log", "*.log"));
        assert!(FimWatcher::matches_pattern("tempfile", "temp*"));
        assert!(!FimWatcher::matches_pattern("test.txt", "*.tmp"));
    }

    #[test]
    fn test_should_ignore_path() {
        let config = WatchConfig::default();
        
        assert!(FimWatcher::should_ignore_path(Path::new("test.tmp"), &config));
        assert!(FimWatcher::should_ignore_path(Path::new("file.log"), &config));
        assert!(FimWatcher::should_ignore_path(Path::new(".git/config"), &config));
        assert!(!FimWatcher::should_ignore_path(Path::new("important.txt"), &config));
    }

    #[test]
    fn test_event_batcher() {
        let mut batcher = EventBatcher::new(3, Duration::from_millis(100));
        
        let event = FimEvent {
            kind: FimEventKind::Created,
            path: PathBuf::from("/test"),
            timestamp: chrono::Utc::now(),
            size: Some(1024),
            is_directory: false,
        };

        // Add events below threshold
        assert!(batcher.add_event(event.clone()).is_none());
        assert!(batcher.add_event(event.clone()).is_none());
        
        // This should trigger flush due to size
        let batch = batcher.add_event(event.clone());
        assert!(batch.is_some());
        assert_eq!(batch.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_basic_watcher_creation() -> Result<()> {
        let temp_dir = tempdir()?;
        
        let config = WatchConfig {
            paths: vec![temp_dir.path().to_path_buf()],
            ..Default::default()
        };
        
        let watcher = FimWatcher::new(config)?;
        let stats = watcher.get_stats();
        
        assert!(!stats.is_running);
        assert_eq!(stats.paths_watched, 1);
        
        Ok(())
    }
}