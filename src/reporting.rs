//! Comprehensive reporting and alerting module for FIM
//! 
//! Provides various output formats for FIM results including JSON, CSV, HTML reports,
//! and integration with external alerting systems.

use crate::fim::{ChangeType, FileChange, ScanResults};
use crate::database::FimStats;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Report generation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    pub title: String,
    pub description: Option<String>,
    pub include_summary: bool,
    pub include_details: bool,
    pub include_statistics: bool,
    pub max_changes_displayed: Option<usize>,
    pub group_by_type: bool,
    pub sort_by: SortOrder,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            title: "File Integrity Monitoring Report".to_string(),
            description: None,
            include_summary: true,
            include_details: true,
            include_statistics: true,
            max_changes_displayed: Some(1000),
            group_by_type: true,
            sort_by: SortOrder::Timestamp,
        }
    }
}

/// Sort order for changes in reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortOrder {
    Timestamp,
    Path,
    ChangeType,
    Size,
}

/// Comprehensive FIM report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimReport {
    pub metadata: ReportMetadata,
    pub summary: ReportSummary,
    pub statistics: Option<FimStats>,
    pub changes: Vec<FileChange>,
    pub scan_results: Option<ScanResults>,
}

/// Report metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub title: String,
    pub description: Option<String>,
    pub generated_at: DateTime<Utc>,
    pub fim_version: String,
    pub scan_period: Option<ScanPeriod>,
    pub configuration: Option<ReportConfiguration>,
}

/// Time period covered by the report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPeriod {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_seconds: u64,
}

/// Configuration information included in report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfiguration {
    pub monitored_paths: Vec<PathBuf>,
    pub exclude_patterns: Vec<String>,
    pub hash_algorithms: Vec<String>,
    pub realtime_enabled: bool,
}

/// Summary statistics for the report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_changes: usize,
    pub changes_by_type: HashMap<String, usize>,
    pub critical_changes: usize,
    pub files_affected: usize,
    pub total_size_changed: u64,
    pub risk_level: RiskLevel,
}

/// Risk assessment levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Output format for reports
#[derive(Debug, Clone)]
pub enum OutputFormat {
    Json,
    Csv,
    Html,
    Text,
    Xml,
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Alert structure for external systems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub severity: AlertSeverity,
    pub title: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub file_path: PathBuf,
    pub change_type: ChangeType,
    pub metadata: HashMap<String, String>,
}

/// Main report generator
pub struct ReportGenerator {
    config: ReportConfig,
}

impl ReportGenerator {
    /// Create new report generator
    pub fn new(config: ReportConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(ReportConfig::default())
    }

    /// Generate comprehensive FIM report
    pub fn generate_report(
        &self,
        changes: Vec<FileChange>,
        scan_results: Option<ScanResults>,
        stats: Option<FimStats>,
    ) -> FimReport {
        let summary = self.generate_summary(&changes);
        
        let metadata = ReportMetadata {
            title: self.config.title.clone(),
            description: self.config.description.clone(),
            generated_at: Utc::now(),
            fim_version: crate::VERSION.to_string(),
            scan_period: scan_results.as_ref().map(|sr| ScanPeriod {
                start_time: Utc::now() - chrono::Duration::from_std(sr.scan_duration).unwrap_or_default(),
                end_time: Utc::now(),
                duration_seconds: sr.scan_duration.as_secs(),
            }),
            configuration: None, // Could be populated from FimConfig
        };

        let mut sorted_changes = changes;
        self.sort_changes(&mut sorted_changes);

        // Limit number of changes if configured
        if let Some(max_changes) = self.config.max_changes_displayed {
            sorted_changes.truncate(max_changes);
        }

        FimReport {
            metadata,
            summary,
            statistics: stats,
            changes: sorted_changes,
            scan_results,
        }
    }

    /// Export report to file in specified format
    pub fn export_report<P: AsRef<Path>>(
        &self,
        report: &FimReport,
        output_path: P,
        format: OutputFormat,
    ) -> Result<()> {
        let content = match format {
            OutputFormat::Json => self.export_json(report)?,
            OutputFormat::Csv => self.export_csv(report)?,
            OutputFormat::Html => self.export_html(report)?,
            OutputFormat::Text => self.export_text(report)?,
            OutputFormat::Xml => self.export_xml(report)?,
        };

        fs::write(output_path, content)?;
        Ok(())
    }

    /// Generate summary statistics
    fn generate_summary(&self, changes: &[FileChange]) -> ReportSummary {
        let mut changes_by_type = HashMap::new();
        let mut files_affected = std::collections::HashSet::new();
        let mut total_size_changed = 0u64;
        let mut critical_changes = 0;

        for change in changes {
            // Count by type
            let type_name = format!("{:?}", change.change_type);
            *changes_by_type.entry(type_name).or_insert(0) += 1;

            // Track affected files
            files_affected.insert(&change.path);

            // Calculate size changes
            if let Some(new_entry) = &change.new_entry {
                total_size_changed += new_entry.size;
            }

            // Count critical changes
            if self.is_critical_change(change) {
                critical_changes += 1;
            }
        }

        let risk_level = self.assess_risk_level(changes, critical_changes);

        ReportSummary {
            total_changes: changes.len(),
            changes_by_type,
            critical_changes,
            files_affected: files_affected.len(),
            total_size_changed,
            risk_level,
        }
    }

    /// Determine if a change is critical
    fn is_critical_change(&self, change: &FileChange) -> bool {
        match change.change_type {
            ChangeType::Deleted => true,
            ChangeType::Added => {
                // New executable files might be critical
                if let Some(path_str) = change.path.to_str() {
                    path_str.contains("/bin/") || path_str.contains("/sbin/")
                } else {
                    false
                }
            }
            ChangeType::HashChanged => true,
            ChangeType::PermissionChanged => {
                // Permission changes on system files are critical
                if let Some(path_str) = change.path.to_str() {
                    path_str.starts_with("/etc/") || 
                    path_str.starts_with("/usr/bin/") ||
                    path_str.starts_with("/usr/sbin/")
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Assess overall risk level
    fn assess_risk_level(&self, changes: &[FileChange], critical_changes: usize) -> RiskLevel {
        let total_changes = changes.len();
        
        if critical_changes > 10 || total_changes > 1000 {
            RiskLevel::Critical
        } else if critical_changes > 5 || total_changes > 100 {
            RiskLevel::High
        } else if critical_changes > 0 || total_changes > 10 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }

    /// Sort changes according to configuration
    fn sort_changes(&self, changes: &mut [FileChange]) {
        match self.config.sort_by {
            SortOrder::Timestamp => {
                changes.sort_by(|a, b| b.detected_at.cmp(&a.detected_at));
            }
            SortOrder::Path => {
                changes.sort_by(|a, b| a.path.cmp(&b.path));
            }
            SortOrder::ChangeType => {
                changes.sort_by(|a, b| {
                    format!("{:?}", a.change_type).cmp(&format!("{:?}", b.change_type))
                });
            }
            SortOrder::Size => {
                changes.sort_by(|a, b| {
                    let size_a = a.new_entry.as_ref().map(|e| e.size).unwrap_or(0);
                    let size_b = b.new_entry.as_ref().map(|e| e.size).unwrap_or(0);
                    size_b.cmp(&size_a)
                });
            }
        }
    }

    /// Export to JSON format
    fn export_json(&self, report: &FimReport) -> Result<String> {
        Ok(serde_json::to_string_pretty(report)?)
    }

    /// Export to CSV format
    fn export_csv(&self, report: &FimReport) -> Result<String> {
        let mut output = String::new();
        
        // CSV header
        output.push_str("timestamp,path,change_type,size,permissions,hash\n");
        
        // CSV data
        for change in &report.changes {
            let size = change.new_entry.as_ref()
                .map(|e| e.size.to_string())
                .unwrap_or_else(|| "".to_string());
            
            let permissions = change.new_entry.as_ref()
                .map(|e| e.perm.clone())
                .unwrap_or_else(|| "".to_string());
            
            let hash = change.new_entry.as_ref()
                .map(|e| e.blake3.clone())
                .unwrap_or_else(|| "".to_string());
            
            output.push_str(&format!(
                "{},{},{:?},{},{},{}\n",
                change.detected_at.format("%Y-%m-%d %H:%M:%S UTC"),
                change.path.display(),
                change.change_type,
                size,
                permissions,
                hash
            ));
        }
        
        Ok(output)
    }

    /// Export to HTML format
    fn export_html(&self, report: &FimReport) -> Result<String> {
        let mut html = String::new();
        
        // HTML header
        html.push_str(&format!(r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f4f4f4; padding: 15px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; padding: 15px; background-color: #e8f4f8; border-radius: 5px; }}
        .risk-level {{ font-weight: bold; }}
        .risk-low {{ color: green; }}
        .risk-medium {{ color: orange; }}
        .risk-high {{ color: red; }}
        .risk-critical {{ color: darkred; background-color: #ffe6e6; padding: 5px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .change-added {{ background-color: #e6ffe6; }}
        .change-modified {{ background-color: #fff4e6; }}
        .change-deleted {{ background-color: #ffe6e6; }}
        .timestamp {{ white-space: nowrap; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{}</h1>
        <p>Generated: {}</p>
        "#, 
        report.metadata.title,
        report.metadata.title,
        report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));

        if let Some(ref description) = report.metadata.description {
            html.push_str(&format!("<p>{}</p>", description));
        }

        html.push_str("</div>");

        // Summary section
        html.push_str(&format!(r#"
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Changes:</strong> {}</p>
        <p><strong>Critical Changes:</strong> {}</p>
        <p><strong>Files Affected:</strong> {}</p>
        <p><strong>Risk Level:</strong> <span class="risk-level risk-{}">{:?}</span></p>
    </div>
        "#, 
        report.summary.total_changes,
        report.summary.critical_changes,
        report.summary.files_affected,
        format!("{:?}", report.summary.risk_level).to_lowercase(),
        report.summary.risk_level
    ));

        // Changes table
        if !report.changes.is_empty() {
            html.push_str(r#"
    <h2>File Changes</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Path</th>
                <th>Change Type</th>
                <th>Size</th>
                <th>Permissions</th>
            </tr>
        </thead>
        <tbody>
            "#);

            for change in &report.changes {
                let row_class = match change.change_type {
                    ChangeType::Added => "change-added",
                    ChangeType::Modified | ChangeType::HashChanged => "change-modified",
                    ChangeType::Deleted => "change-deleted",
                    _ => "",
                };

                let size = change.new_entry.as_ref()
                    .map(|e| crate::utils::format_size(e.size))
                    .unwrap_or_else(|| "-".to_string());

                let permissions = change.new_entry.as_ref()
                    .map(|e| e.perm.clone())
                    .unwrap_or_else(|| "-".to_string());

                html.push_str(&format!(
                    r#"<tr class="{}">
                        <td class="timestamp">{}</td>
                        <td>{}</td>
                        <td>{:?}</td>
                        <td>{}</td>
                        <td>{}</td>
                    </tr>"#,
                    row_class,
                    change.detected_at.format("%Y-%m-%d %H:%M:%S"),
                    change.path.display(),
                    change.change_type,
                    size,
                    permissions
                ));
            }

            html.push_str("</tbody></table>");
        }

        html.push_str("</body></html>");
        Ok(html)
    }

    /// Export to plain text format
    fn export_text(&self, report: &FimReport) -> Result<String> {
        let mut output = String::new();
        
        output.push_str(&format!("=== {} ===\n", report.metadata.title));
        output.push_str(&format!("Generated: {}\n\n", 
            report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC")));

        // Summary
        output.push_str("SUMMARY\n");
        output.push_str(&format!("Total Changes: {}\n", report.summary.total_changes));
        output.push_str(&format!("Critical Changes: {}\n", report.summary.critical_changes));
        output.push_str(&format!("Files Affected: {}\n", report.summary.files_affected));
        output.push_str(&format!("Risk Level: {:?}\n\n", report.summary.risk_level));

        // Changes by type
        if !report.summary.changes_by_type.is_empty() {
            output.push_str("CHANGES BY TYPE\n");
            for (change_type, count) in &report.summary.changes_by_type {
                output.push_str(&format!("{}: {}\n", change_type, count));
            }
            output.push('\n');
        }

        // Detailed changes
        if !report.changes.is_empty() {
            output.push_str("DETAILED CHANGES\n");
            for change in &report.changes {
                output.push_str(&format!(
                    "[{}] {:?}: {}\n",
                    change.detected_at.format("%Y-%m-%d %H:%M:%S"),
                    change.change_type,
                    change.path.display()
                ));
            }
        }

        Ok(output)
    }

    /// Export to XML format
    fn export_xml(&self, report: &FimReport) -> Result<String> {
        let mut xml = String::new();
        
        xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>
<fim_report>
"#);

        // Metadata
        xml.push_str(&format!(r#"  <metadata>
    <title>{}</title>
    <generated_at>{}</generated_at>
    <fim_version>{}</fim_version>
  </metadata>
"#, 
        report.metadata.title,
        report.metadata.generated_at.to_rfc3339(),
        report.metadata.fim_version
    ));

        // Summary
        xml.push_str(&format!(r#"  <summary>
    <total_changes>{}</total_changes>
    <critical_changes>{}</critical_changes>
    <files_affected>{}</files_affected>
    <risk_level>{:?}</risk_level>
  </summary>
"#,
        report.summary.total_changes,
        report.summary.critical_changes,
        report.summary.files_affected,
        report.summary.risk_level
    ));

        // Changes
        xml.push_str("  <changes>\n");
        for change in &report.changes {
            xml.push_str(&format!(r#"    <change>
      <timestamp>{}</timestamp>
      <path>{}</path>
      <type>{:?}</type>
    </change>
"#,
            change.detected_at.to_rfc3339(),
            change.path.display(),
            change.change_type
        ));
        }
        xml.push_str("  </changes>\n");

        xml.push_str("</fim_report>\n");
        Ok(xml)
    }
}

/// Alert generator for external system integration
pub struct AlertGenerator {
    severity_rules: HashMap<ChangeType, AlertSeverity>,
}

impl AlertGenerator {
    /// Create new alert generator with default severity rules
    pub fn new() -> Self {
        let mut severity_rules = HashMap::new();
        severity_rules.insert(ChangeType::Deleted, AlertSeverity::Critical);
        severity_rules.insert(ChangeType::HashChanged, AlertSeverity::Error);
        severity_rules.insert(ChangeType::Added, AlertSeverity::Warning);
        severity_rules.insert(ChangeType::PermissionChanged, AlertSeverity::Warning);
        severity_rules.insert(ChangeType::Modified, AlertSeverity::Info);
        severity_rules.insert(ChangeType::SizeChanged, AlertSeverity::Info);
        severity_rules.insert(ChangeType::TimestampChanged, AlertSeverity::Info);

        Self { severity_rules }
    }

    /// Generate alert from file change
    pub fn generate_alert(&self, change: &FileChange) -> Alert {
        let severity = self.severity_rules.get(&change.change_type)
            .cloned()
            .unwrap_or(AlertSeverity::Info);

        let title = format!("File {:?}: {}", change.change_type, change.path.display());
        let message = self.format_alert_message(change);

        let mut metadata = HashMap::new();
        if let Some(ref new_entry) = change.new_entry {
            metadata.insert("size".to_string(), new_entry.size.to_string());
            metadata.insert("permissions".to_string(), new_entry.perm.clone());
            metadata.insert("hash".to_string(), new_entry.blake3.clone());
        }

        Alert {
            id: format!("fim_{}_{}", 
                change.detected_at.timestamp(),
                blake3::hash(change.path.to_string_lossy().as_bytes()).to_hex().to_string()[..8].to_string()
            ),
            severity,
            title,
            message,
            timestamp: change.detected_at,
            file_path: change.path.clone(),
            change_type: change.change_type.clone(),
            metadata,
        }
    }

    /// Format detailed alert message
    fn format_alert_message(&self, change: &FileChange) -> String {
        match change.change_type {
            ChangeType::Added => {
                format!("New file created: {}", change.path.display())
            }
            ChangeType::Deleted => {
                format!("File deleted: {}", change.path.display())
            }
            ChangeType::HashChanged => {
                format!("File content modified: {}", change.path.display())
            }
            ChangeType::PermissionChanged => {
                let old_perm = change.old_entry.as_ref().map(|e| &e.perm).unwrap_or(&"unknown".to_string());
                let new_perm = change.new_entry.as_ref().map(|e| &e.perm).unwrap_or(&"unknown".to_string());
                format!("Permissions changed: {} ({} -> {})", 
                    change.path.display(), old_perm, new_perm)
            }
            _ => {
                format!("File modified: {}", change.path.display())
            }
        }
    }

    /// Send alert to external system (placeholder implementation)
    pub fn send_alert(&self, alert: &Alert) -> Result<()> {
        // This would integrate with external alerting systems like:
        // - Syslog
        // - SIEM systems
        // - Slack/Teams webhooks
        // - Email notifications
        // - HTTP endpoints
        
        info!("Alert generated: {:?} - {}", alert.severity, alert.title);
        debug!("Alert details: {:?}", alert);
        
        // Example: Send to syslog
        #[cfg(unix)]
        {
            use std::process::Command;
            let _ = Command::new("logger")
                .arg("-t")
                .arg("fim")
                .arg(&format!("{:?}: {}", alert.severity, alert.message))
                .output();
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::path::PathBuf;

    fn create_test_change() -> FileChange {
        use crate::database::FimEntryData;
        
        FileChange {
            path: PathBuf::from("/test/file.txt"),
            change_type: ChangeType::HashChanged,
            old_entry: None,
            new_entry: Some(FimEntryData {
                size: 1024,
                perm: "644".to_string(),
                uid: 1000,
                gid: 1000,
                md5: None,
                sha1: None,
                sha256: None,
                blake3: "test_hash".to_string(),
                mtime: Utc::now(),
                ctime: Utc::now(),
                atime: Utc::now(),
                inode: 12345,
                dev: 2049,
                scanned: true,
            }),
            detected_at: Utc::now(),
        }
    }

    #[test]
    fn test_report_generation() {
        let generator = ReportGenerator::default();
        let changes = vec![create_test_change()];
        
        let report = generator.generate_report(changes, None, None);
        
        assert_eq!(report.summary.total_changes, 1);
        assert!(report.summary.changes_by_type.contains_key("HashChanged"));
    }

    #[test]
    fn test_risk_assessment() {
        let generator = ReportGenerator::default();
        
        // Test low risk
        let low_risk_changes = vec![create_test_change()];
        let summary = generator.generate_summary(&low_risk_changes);
        assert_eq!(summary.risk_level, RiskLevel::Medium); // HashChanged is critical
        
        // Test critical risk
        let mut critical_change = create_test_change();
        critical_change.change_type = ChangeType::Deleted;
        let critical_changes = vec![critical_change; 15];
        let summary = generator.generate_summary(&critical_changes);
        assert_eq!(summary.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_export_formats() -> Result<()> {
        let generator = ReportGenerator::default();
        let changes = vec![create_test_change()];
        let report = generator.generate_report(changes, None, None);
        
        let temp_dir = tempdir()?;
        
        // Test JSON export
        let json_path = temp_dir.path().join("report.json");
        generator.export_report(&report, &json_path, OutputFormat::Json)?;
        assert!(json_path.exists());
        
        // Test CSV export
        let csv_path = temp_dir.path().join("report.csv");
        generator.export_report(&report, &csv_path, OutputFormat::Csv)?;
        assert!(csv_path.exists());
        
        // Test HTML export
        let html_path = temp_dir.path().join("report.html");
        generator.export_report(&report, &html_path, OutputFormat::Html)?;
        assert!(html_path.exists());
        
        Ok(())
    }

    #[test]
    fn test_alert_generation() {
        let generator = AlertGenerator::new();
        let change = create_test_change();
        
        let alert = generator.generate_alert(&change);
        
        assert_eq!(alert.severity, AlertSeverity::Error); // HashChanged -> Error
        assert!(!alert.id.is_empty());
        assert!(alert.title.contains("HashChanged"));
    }
}