//! High-Performance File Integrity Monitoring (FIM) System
//! 
//! A modern, fast, and reliable file integrity monitoring system written in Rust.
//! Features BLAKE3 hashing, SQLite storage, real-time monitoring, and comprehensive CLI.

mod database;
mod fim;
mod hasher;
mod watcher;

use crate::fim::{FimConfig, FimEngine, FimMode, ChangeType};
use crate::hasher::HashConfig;
use crate::watcher::WatchConfig;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tracing::{error, info, warn, Level};
use tracing_subscriber;

#[derive(Parser)]
#[command(
    name = "fim",
    version = "0.1.0",
    about = "High-Performance File Integrity Monitoring System",
    long_about = "A modern FIM system featuring BLAKE3 hashing, SQLite storage, \
                  real-time monitoring, and comprehensive integrity checking."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Logging level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Use in-memory database (no persistence)
    #[arg(long)]
    memory_db: bool,

    /// Number of scanning threads
    #[arg(short, long)]
    threads: Option<usize>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform initial baseline scan
    Baseline {
        /// Paths to monitor
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Exclude patterns (glob format)
        #[arg(short, long)]
        exclude: Vec<String>,

        /// Maximum file size to process (MB)
        #[arg(long, default_value = "1024")]
        max_size_mb: u64,

        /// Output baseline to JSON file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Perform incremental scan
    Scan {
        /// Paths to scan (uses baseline if not specified)
        paths: Vec<PathBuf>,

        /// Only show changes, not all files
        #[arg(long)]
        changes_only: bool,

        /// Output format
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Start real-time monitoring
    Monitor {
        /// Paths to monitor (uses baseline if not specified)
        paths: Vec<PathBuf>,

        /// Exclude patterns
        #[arg(short, long)]
        exclude: Vec<String>,

        /// Scan interval in seconds for periodic checks
        #[arg(long, default_value = "3600")]
        interval: u64,

        /// Output alerts to file
        #[arg(long)]
        alerts_file: Option<PathBuf>,
    },

    /// Verify file integrity
    Verify {
        /// Specific file or directory to verify
        path: Option<PathBuf>,

        /// Verify against specific hash
        #[arg(long)]
        hash: Option<String>,

        /// Show detailed verification results
        #[arg(long)]
        detailed: bool,
    },

    /// Database operations
    Db {
        #[command(subcommand)]
        action: DbCommands,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },

    /// Show statistics and status
    Status {
        /// Show detailed statistics
        #[arg(long)]
        detailed: bool,
    },
}

#[derive(Subcommand)]
enum DbCommands {
    /// Show database statistics
    Stats,
    /// Export database to JSON
    Export {
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Import database from JSON
    Import {
        /// Input file path
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Clean/reset database
    Clean {
        /// Force cleanup without confirmation
        #[arg(long)]
        force: bool,
    },
    /// Verify database integrity
    Verify,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Generate default configuration file
    Init {
        /// Output configuration file
        #[arg(short, long, default_value = "fim.toml")]
        output: PathBuf,
    },
    /// Validate configuration file
    Validate {
        /// Configuration file to validate
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Show current configuration
    Show,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli.log_level, cli.verbose)?;

    // Load configuration
    let mut config = load_config(&cli)?;
    
    // Override config with CLI parameters
    if cli.memory_db {
        config.memory_database = true;
    }
    
    if let Some(threads) = cli.threads {
        config.scan_threads = Some(threads);
    }

    // Execute commands
    match cli.command {
        Commands::Baseline { paths, exclude, max_size_mb, output } => {
            handle_baseline(config, paths, exclude, max_size_mb, output).await
        }
        Commands::Scan { paths, changes_only, format } => {
            handle_scan(config, paths, changes_only, format).await
        }
        Commands::Monitor { paths, exclude, interval, alerts_file } => {
            handle_monitor(config, paths, exclude, interval, alerts_file).await
        }
        Commands::Verify { path, hash, detailed } => {
            handle_verify(config, path, hash, detailed).await
        }
        Commands::Db { action } => {
            handle_db_commands(config, action).await
        }
        Commands::Config { action } => {
            handle_config_commands(action).await
        }
        Commands::Status { detailed } => {
            handle_status(config, detailed).await
        }
    }
}

async fn handle_baseline(
    mut config: FimConfig,
    paths: Vec<PathBuf>,
    exclude: Vec<String>,
    max_size_mb: u64,
    output: Option<PathBuf>,
) -> Result<()> {
    info!("Starting baseline scan for {} paths", paths.len());

    config.monitor_paths = paths;
    config.exclude_patterns.extend(exclude);
    config.max_file_size = Some(max_size_mb * 1024 * 1024);

    let mut engine = FimEngine::new(config)?;
    engine.start()?;

    // Add change handler for reporting
    engine.add_change_handler(|change| {
        match change.change_type {
            ChangeType::Added => {
                println!("+ {}", change.path.display());
            }
            _ => {}
        }
    });

    let results = engine.baseline_scan()?;

    println!("\n=== Baseline Scan Results ===");
    println!("Files scanned: {}", results.files_scanned);
    println!("Files added: {}", results.files_added);
    println!("Total size: {} MB", results.total_size / (1024 * 1024));
    println!("Scan duration: {:?}", results.scan_duration);
    println!("Errors: {}", results.errors);

    if let Some(output_path) = output {
        engine.export_database(&output_path)?;
        println!("Baseline exported to: {}", output_path.display());
    }

    Ok(())
}

async fn handle_scan(
    mut config: FimConfig,
    paths: Vec<PathBuf>,
    changes_only: bool,
    format: String,
) -> Result<()> {
    if !paths.is_empty() {
        config.monitor_paths = paths;
    }

    let mut engine = FimEngine::new(config)?;
    engine.start()?;

    // Add change handler for reporting
    let changes_only_flag = changes_only;
    engine.add_change_handler(move |change| {
        if changes_only_flag {
            match change.change_type {
                ChangeType::Added => println!("+ {}", change.path.display()),
                ChangeType::Modified | ChangeType::HashChanged => {
                    println!("M {}", change.path.display());
                }
                ChangeType::Deleted => println!("- {}", change.path.display()),
                ChangeType::PermissionChanged => println!("P {}", change.path.display()),
                ChangeType::SizeChanged => println!("S {}", change.path.display()),
                ChangeType::TimestampChanged => println!("T {}", change.path.display()),
            }
        } else {
            println!("{:?}: {}", change.change_type, change.path.display());
        }
    });

    let results = engine.incremental_scan()?;

    if !changes_only {
        println!("\n=== Scan Results ===");
        println!("Files scanned: {}", results.files_scanned);
        println!("Files added: {}", results.files_added);
        println!("Files modified: {}", results.files_modified);
        println!("Files deleted: {}", results.files_deleted);
        println!("Scan duration: {:?}", results.scan_duration);
        println!("Errors: {}", results.errors);
    }

    Ok(())
}

async fn handle_monitor(
    mut config: FimConfig,
    paths: Vec<PathBuf>,
    exclude: Vec<String>,
    interval: u64,
    alerts_file: Option<PathBuf>,
) -> Result<()> {
    info!("Starting real-time monitoring");

    if !paths.is_empty() {
        config.monitor_paths = paths;
    }
    config.exclude_patterns.extend(exclude);
    config.scan_interval = interval;
    config.enable_realtime = true;

    let mut engine = FimEngine::new(config)?;

    // Setup change handler for alerts
    let alerts_file_clone = alerts_file.clone();
    engine.add_change_handler(move |change| {
        let alert_msg = format!(
            "[{}] {:?}: {}",
            change.detected_at.format("%Y-%m-%d %H:%M:%S UTC"),
            change.change_type,
            change.path.display()
        );

        println!("{}", alert_msg);

        // Write to alerts file if specified
        if let Some(ref alerts_file) = alerts_file_clone {
            if let Err(e) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(alerts_file)
                .and_then(|mut f| {
                    use std::io::Write;
                    writeln!(f, "{}", alert_msg)
                })
            {
                error!("Failed to write to alerts file: {}", e);
            }
        }
    });

    engine.start()?;

    // Setup periodic scanning
    let engine_arc = Arc::new(tokio::sync::Mutex::new(engine));
    let scan_engine = engine_arc.clone();
    
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval));
        loop {
            interval.tick().await;
            info!("Performing periodic scan");
            
            let mut engine = scan_engine.lock().await;
            match engine.incremental_scan() {
                Ok(results) => {
                    info!("Periodic scan completed: {} files, {} changes", 
                          results.files_scanned,
                          results.files_added + results.files_modified + results.files_deleted);
                }
                Err(e) => {
                    error!("Periodic scan failed: {}", e);
                }
            }
        }
    });

    // Process real-time events
    tokio::spawn(async move {
        let mut engine = engine_arc.lock().await;
        if let Err(e) = engine.process_realtime_events() {
            error!("Real-time monitoring failed: {}", e);
        }
    });

    // Wait for shutdown signal
    println!("FIM monitoring active. Press Ctrl+C to stop.");
    signal::ctrl_c().await?;
    println!("Shutting down...");

    Ok(())
}

async fn handle_verify(
    config: FimConfig,
    path: Option<PathBuf>,
    hash: Option<String>,
    detailed: bool,
) -> Result<()> {
    let engine = FimEngine::new(config)?;

    if let Some(path) = path {
        if let Some(expected_hash) = hash {
            // Verify specific file against hash
            let hasher = crate::hasher::FileHasher::blake3_only();
            match hasher.verify_file(&path, &expected_hash) {
                Ok(true) => {
                    println!("✓ {} - VERIFIED", path.display());
                }
                Ok(false) => {
                    println!("✗ {} - VERIFICATION FAILED", path.display());
                }
                Err(e) => {
                    error!("Verification error for {}: {}", path.display(), e);
                }
            }
        } else {
            // Verify against database
            println!("Verifying {} against database", path.display());
            // Implementation would check against stored hash
        }
    } else {
        // Verify entire database integrity
        let checksum = engine.verify_integrity()?;
        println!("Database integrity checksum: {}", checksum);
        
        if detailed {
            let stats = engine.get_stats()?;
            println!("Total files in database: {}", stats.total_files);
            println!("Scanned files: {}", stats.scanned_files);
            println!("Unscanned files: {}", stats.unscanned_files);
        }
    }

    Ok(())
}

async fn handle_db_commands(config: FimConfig, action: DbCommands) -> Result<()> {
    let engine = FimEngine::new(config)?;

    match action {
        DbCommands::Stats => {
            let stats = engine.get_stats()?;
            println!("=== Database Statistics ===");
            println!("Total files: {}", stats.total_files);
            println!("Scanned files: {}", stats.scanned_files);
            println!("Unscanned files: {}", stats.unscanned_files);
        }
        DbCommands::Export { output } => {
            engine.export_database(&output)?;
            println!("Database exported to: {}", output.display());
        }
        DbCommands::Import { input: _ } => {
            // Implementation would import from JSON
            println!("Database import functionality not yet implemented");
        }
        DbCommands::Clean { force } => {
            if force || confirm_action("This will delete all FIM data. Continue?")? {
                crate::database::FimDb::clean()?;
                println!("Database cleaned successfully");
            }
        }
        DbCommands::Verify => {
            let checksum = engine.verify_integrity()?;
            println!("Database integrity verified");
            println!("Checksum: {}", checksum);
        }
    }

    Ok(())
}

async fn handle_config_commands(action: ConfigCommands) -> Result<()> {
    match action {
        ConfigCommands::Init { output } => {
            let default_config = FimConfig::default();
            let config_toml = toml::to_string_pretty(&default_config)?;
            std::fs::write(&output, config_toml)?;
            println!("Default configuration written to: {}", output.display());
        }
        ConfigCommands::Validate { file } => {
            let content = std::fs::read_to_string(&file)?;
            let _config: FimConfig = toml::from_str(&content)
                .context("Invalid configuration file")?;
            println!("Configuration file is valid");
        }
        ConfigCommands::Show => {
            let config = FimConfig::default();
            println!("{}", toml::to_string_pretty(&config)?);
        }
    }

    Ok(())
}

async fn handle_status(config: FimConfig, detailed: bool) -> Result<()> {
    let engine = FimEngine::new(config)?;
    let stats = engine.get_stats()?;

    println!("=== FIM Status ===");
    println!("Total files monitored: {}", stats.total_files);
    println!("Files up to date: {}", stats.scanned_files);
    
    if stats.unscanned_files > 0 {
        println!("Files requiring scan: {}", stats.unscanned_files);
    }

    if detailed {
        println!("\n=== Detailed Information ===");
        // Additional detailed stats would go here
        println!("Database integrity: {}", engine.verify_integrity()?);
    }

    Ok(())
}

fn load_config(cli: &Cli) -> Result<FimConfig> {
    if let Some(config_path) = &cli.config {
        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;
        
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", config_path.display()))
    } else {
        Ok(FimConfig::default())
    }
}

fn init_logging(level: &str, verbose: bool) -> Result<()> {
    let log_level = if verbose {
        Level::DEBUG
    } else {
        match level.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        }
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    Ok(())
}

fn confirm_action(message: &str) -> Result<bool> {
    use std::io::{self, Write};
    
    print!("{} [y/N]: ", message);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    Ok(input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes")
}