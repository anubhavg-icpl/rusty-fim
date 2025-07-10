//! Complete FIM demonstration showing all major features
//! 
//! This example demonstrates:
//! - Setting up FIM monitoring
//! - Performing baseline and incremental scans
//! - Real-time monitoring with change detection
//! - Generating comprehensive reports
//! - Integrating with alerting systems

use rusty_fim::prelude::*;
use rusty_fim::reporting::{OutputFormat, ReportGenerator};

use anyhow::Result;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;
use tokio::time;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    rusty_fim::init_logging()?;
    
    println!("🛡️  Rusty FIM - Complete Demo");
    println!("============================\n");

    // Create temporary directory for demonstration
    let demo_dir = tempdir()?;
    println!("📁 Demo directory: {}", demo_dir.path().display());

    // Setup initial files
    setup_demo_files(&demo_dir.path().to_path_buf()).await?;

    // Configure FIM
    let config = create_demo_config(&demo_dir.path().to_path_buf())?;
    
    // Run the complete demo
    run_fim_demo(config, demo_dir.path().to_path_buf()).await?;

    println!("\n✅ Demo completed successfully!");
    Ok(())
}

/// Create demonstration files and directory structure
async fn setup_demo_files(demo_dir: &PathBuf) -> Result<()> {
    println!("📝 Setting up demo files...");

    // Create subdirectories
    let config_dir = demo_dir.join("config");
    let data_dir = demo_dir.join("data");
    let logs_dir = demo_dir.join("logs");
    
    fs::create_dir_all(&config_dir)?;
    fs::create_dir_all(&data_dir)?;
    fs::create_dir_all(&logs_dir)?;

    // Create configuration files
    fs::write(
        config_dir.join("app.conf"),
        "# Application Configuration\ndebug=true\nport=8080\n"
    )?;
    
    fs::write(
        config_dir.join("database.conf"),
        "# Database Configuration\nhost=localhost\nport=5432\n"
    )?;

    // Create data files
    fs::write(
        data_dir.join("important.txt"),
        "This is critical business data that should not change."
    )?;
    
    fs::write(
        data_dir.join("users.json"),
        r#"{"users": [{"id": 1, "name": "admin"}, {"id": 2, "name": "user"}]}"#
    )?;

    // Create log files (these will be excluded from monitoring)
    fs::write(
        logs_dir.join("application.log"),
        "2025-01-01 10:00:00 INFO Application started\n"
    )?;

    println!("✅ Demo files created");
    Ok(())
}

/// Create FIM configuration for the demo
fn create_demo_config(demo_dir: &PathBuf) -> Result<FimConfig> {
    let mut config = FimConfig::default();
    
    // Monitor the demo directory
    config.monitor_paths = vec![demo_dir.clone()];
    
    // Exclude log files and temporary files
    config.exclude_patterns = vec![
        "**/logs/**".to_string(),
        "**/*.tmp".to_string(),
        "**/*.temp".to_string(),
    ];
    
    // Use in-memory database for demo
    config.memory_database = true;
    
    // Enable real-time monitoring
    config.enable_realtime = true;
    config.scan_interval = 10; // Short interval for demo
    
    // Configure hashing
    config.hash_config.use_blake3 = true;
    config.hash_config.use_sha256 = true; // For demonstration
    
    // Configure watching
    config.watch_config.debounce_timeout = Duration::from_millis(100);
    config.watch_config.recursive = true;
    
    Ok(config)
}

/// Run the complete FIM demonstration
async fn run_fim_demo(config: FimConfig, demo_dir: PathBuf) -> Result<()> {
    // Phase 1: Baseline Scan
    println!("\n🔍 Phase 1: Baseline Scan");
    println!("========================");
    
    let baseline_results = perform_baseline_scan(config.clone()).await?;
    print_scan_results(&baseline_results, "Baseline");

    // Phase 2: Incremental Scan (no changes expected)
    println!("\n🔄 Phase 2: Incremental Scan (No Changes)");
    println!("========================================");
    
    let incremental_results = perform_incremental_scan(config.clone()).await?;
    print_scan_results(&incremental_results, "Incremental");

    // Phase 3: Simulate file changes
    println!("\n📝 Phase 3: Simulating File Changes");
    println!("==================================");
    
    simulate_file_changes(&demo_dir).await?;
    
    // Small delay to ensure changes are detected
    time::sleep(Duration::from_millis(500)).await;

    // Phase 4: Incremental scan with changes
    println!("\n🔄 Phase 4: Incremental Scan (With Changes)");
    println!("==========================================");
    
    let changes_results = perform_incremental_scan(config.clone()).await?;
    print_scan_results(&changes_results, "With Changes");

    // Phase 5: Real-time monitoring demonstration
    println!("\n⚡ Phase 5: Real-time Monitoring Demo");
    println!("===================================");
    
    demonstrate_realtime_monitoring(config.clone(), demo_dir.clone()).await?;

    // Phase 6: Report generation
    println!("\n📊 Phase 6: Report Generation");
    println!("============================");
    
    generate_demo_reports(&demo_dir).await?;

    Ok(())
}

/// Perform baseline scan
async fn perform_baseline_scan(config: FimConfig) -> Result<ScanResults> {
    let mut engine = FimEngine::new(config)?;
    
    // Add change handler for baseline
    engine.add_change_handler(|change| {
        println!("  📁 Added: {}", change.path.display());
    });
    
    engine.start()?;
    let results = engine.baseline_scan()?;
    
    Ok(results)
}

/// Perform incremental scan
async fn perform_incremental_scan(config: FimConfig) -> Result<ScanResults> {
    let mut engine = FimEngine::new(config)?;
    
    // Add change handler for incremental scan
    engine.add_change_handler(|change| {
        let icon = match change.change_type {
            ChangeType::Added => "➕",
            ChangeType::Modified | ChangeType::HashChanged => "🔄",
            ChangeType::Deleted => "❌",
            ChangeType::PermissionChanged => "🔐",
            ChangeType::SizeChanged => "📏",
            ChangeType::TimestampChanged => "⏰",
        };
        println!("  {} {:?}: {}", icon, change.change_type, change.path.display());
    });
    
    engine.start()?;
    let results = engine.incremental_scan()?;
    
    Ok(results)
}

/// Simulate various file changes for demonstration
async fn simulate_file_changes(demo_dir: &PathBuf) -> Result<()> {
    println!("  📝 Modifying important.txt...");
    fs::write(
        demo_dir.join("data").join("important.txt"),
        "This is critical business data that HAS BEEN MODIFIED!"
    )?;
    
    println!("  ➕ Adding new configuration file...");
    fs::write(
        demo_dir.join("config").join("security.conf"),
        "# Security Configuration\nssl_enabled=true\nencryption=AES256\n"
    )?;
    
    println!("  ❌ Removing database configuration...");
    let db_config_path = demo_dir.join("config").join("database.conf");
    if db_config_path.exists() {
        fs::remove_file(db_config_path)?;
    }
    
    println!("  🔐 Changing permissions...");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let app_config_path = demo_dir.join("config").join("app.conf");
        let mut perms = fs::metadata(&app_config_path)?.permissions();
        perms.set_mode(0o600); // Make it read-write for owner only
        fs::set_permissions(&app_config_path, perms)?;
    }
    
    Ok(())
}

/// Demonstrate real-time monitoring
async fn demonstrate_realtime_monitoring(config: FimConfig, demo_dir: PathBuf) -> Result<()> {
    println!("  🔄 Starting real-time monitoring for 10 seconds...");
    
    // Track changes in a shared container
    let changes = Arc::new(Mutex::new(Vec::new()));
    let changes_clone = changes.clone();
    
    let mut engine = FimEngine::new(config)?;
    
    // Add change handler that collects changes
    engine.add_change_handler(move |change| {
        println!("    🚨 Real-time change detected: {:?} - {}", 
                 change.change_type, change.path.display());
        
        let mut changes = changes_clone.lock().unwrap();
        changes.push(change.clone());
    });
    
    engine.start()?;
    
    // Spawn monitoring task
    let monitoring_task = tokio::spawn(async move {
        if let Err(e) = engine.process_realtime_events() {
            eprintln!("Monitoring error: {}", e);
        }
    });
    
    // Simulate real-time changes
    tokio::spawn(async move {
        time::sleep(Duration::from_secs(2)).await;
        
        println!("    📝 Creating real-time test file...");
        if let Err(e) = fs::write(
            demo_dir.join("realtime_test.txt"),
            "This file was created during real-time monitoring"
        ) {
            eprintln!("Failed to create real-time test file: {}", e);
        }
        
        time::sleep(Duration::from_secs(2)).await;
        
        println!("    🔄 Modifying real-time test file...");
        if let Err(e) = fs::write(
            demo_dir.join("realtime_test.txt"),
            "This file was MODIFIED during real-time monitoring"
        ) {
            eprintln!("Failed to modify real-time test file: {}", e);
        }
        
        time::sleep(Duration::from_secs(2)).await;
        
        println!("    ❌ Deleting real-time test file...");
        let test_file_path = demo_dir.join("realtime_test.txt");
        if test_file_path.exists() {
            if let Err(e) = fs::remove_file(test_file_path) {
                eprintln!("Failed to delete real-time test file: {}", e);
            }
        }
    });
    
    // Wait for demonstration period
    time::sleep(Duration::from_secs(10)).await;
    
    // Stop monitoring
    monitoring_task.abort();
    
    let final_changes = changes.lock().unwrap();
    println!("  ✅ Real-time monitoring completed. Detected {} changes.", final_changes.len());
    
    Ok(())
}

/// Generate demonstration reports in various formats
async fn generate_demo_reports(demo_dir: &PathBuf) -> Result<()> {
    // Create some mock changes for the report
    let mock_changes = create_mock_changes();
    
    // Create report generator
    let mut report_config = ReportConfig::default();
    report_config.title = "Rusty FIM Demo Report".to_string();
    report_config.description = Some("Demonstration of FIM capabilities and change detection".to_string());
    
    let generator = ReportGenerator::new(report_config);
    
    // Generate report
    let report = generator.generate_report(mock_changes, None, None);
    
    println!("  📊 Generating reports in multiple formats...");
    
    // Export JSON report
    let json_path = demo_dir.join("fim_report.json");
    generator.export_report(&report, &json_path, OutputFormat::Json)?;
    println!("    ✅ JSON report: {}", json_path.display());
    
    // Export HTML report
    let html_path = demo_dir.join("fim_report.html");
    generator.export_report(&report, &html_path, OutputFormat::Html)?;
    println!("    ✅ HTML report: {}", html_path.display());
    
    // Export CSV report
    let csv_path = demo_dir.join("fim_report.csv");
    generator.export_report(&report, &csv_path, OutputFormat::Csv)?;
    println!("    ✅ CSV report: {}", csv_path.display());
    
    // Export text report
    let text_path = demo_dir.join("fim_report.txt");
    generator.export_report(&report, &text_path, OutputFormat::Text)?;
    println!("    ✅ Text report: {}", text_path.display());
    
    // Display report summary
    println!("\n  📋 Report Summary:");
    println!("    Total changes: {}", report.summary.total_changes);
    println!("    Critical changes: {}", report.summary.critical_changes);
    println!("    Risk level: {:?}", report.summary.risk_level);
    
    // Demonstrate alerting
    demonstrate_alerting(&mock_changes).await?;
    
    Ok(())
}

/// Create mock changes for report demonstration
fn create_mock_changes() -> Vec<FileChange> {
    use rusty_fim::database::FimEntryData;
    use chrono::Utc;
    
    vec![
        FileChange {
            path: PathBuf::from("/demo/config/app.conf"),
            change_type: ChangeType::Modified,
            old_entry: None,
            new_entry: Some(FimEntryData {
                size: 256,
                perm: "644".to_string(),
                uid: 1000,
                gid: 1000,
                md5: None,
                sha1: None,
                sha256: Some("abc123".to_string()),
                blake3: "def456".to_string(),
                mtime: Utc::now(),
                ctime: Utc::now(),
                atime: Utc::now(),
                inode: 12345,
                dev: 2049,
                scanned: true,
            }),
            detected_at: Utc::now(),
        },
        FileChange {
            path: PathBuf::from("/demo/data/important.txt"),
            change_type: ChangeType::HashChanged,
            old_entry: None,
            new_entry: Some(FimEntryData {
                size: 512,
                perm: "600".to_string(),
                uid: 1000,
                gid: 1000,
                md5: None,
                sha1: None,
                sha256: Some("xyz789".to_string()),
                blake3: "uvw012".to_string(),
                mtime: Utc::now(),
                ctime: Utc::now(),
                atime: Utc::now(),
                inode: 54321,
                dev: 2049,
                scanned: true,
            }),
            detected_at: Utc::now(),
        },
        FileChange {
            path: PathBuf::from("/demo/config/database.conf"),
            change_type: ChangeType::Deleted,
            old_entry: Some(FimEntryData {
                size: 128,
                perm: "644".to_string(),
                uid: 1000,
                gid: 1000,
                md5: None,
                sha1: None,
                sha256: Some("old123".to_string()),
                blake3: "old456".to_string(),
                mtime: Utc::now(),
                ctime: Utc::now(),
                atime: Utc::now(),
                inode: 67890,
                dev: 2049,
                scanned: true,
            }),
            new_entry: None,
            detected_at: Utc::now(),
        },
    ]
}

/// Demonstrate alert generation and handling
async fn demonstrate_alerting(changes: &[FileChange]) -> Result<()> {
    println!("\n  🚨 Alert Generation Demo:");
    
    let alert_generator = AlertGenerator::new();
    
    for change in changes {
        let alert = alert_generator.generate_alert(change);
        
        println!("    {} [{}] {}", 
                 alert_severity_icon(&alert.severity),
                 format!("{:?}", alert.severity).to_uppercase(),
                 alert.title);
        
        // Send alert (this would integrate with real alerting systems)
        alert_generator.send_alert(&alert)?;
    }
    
    Ok(())
}

/// Get icon for alert severity
fn alert_severity_icon(severity: &AlertSeverity) -> &'static str {
    match severity {
        AlertSeverity::Info => "ℹ️",
        AlertSeverity::Warning => "⚠️",
        AlertSeverity::Error => "❌",
        AlertSeverity::Critical => "🚨",
    }
}

/// Print scan results in a formatted way
fn print_scan_results(results: &ScanResults, scan_type: &str) {
    println!("  {} Scan Results:", scan_type);
    println!("    Files scanned: {}", results.files_scanned);
    println!("    Files added: {}", results.files_added);
    println!("    Files modified: {}", results.files_modified);
    println!("    Files deleted: {}", results.files_deleted);
    println!("    Errors: {}", results.errors);
    println!("    Duration: {:?}", results.scan_duration);
    println!("    Total size: {}", format_bytes(results.total_size));
}

/// Format bytes in human-readable format
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
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