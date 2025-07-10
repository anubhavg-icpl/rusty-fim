//! Database layer for File Integrity Monitoring
//! 
//! Implements SQLite-based storage with optimized queries for FIM operations.
//! Based on the Wazuh FIM PoC but with enhanced Rust patterns and performance.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

pub const FIMDB_OK: i32 = 0;
pub const FIMDB_ERR: i32 = -1;

/// File entry data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimEntryData {
    pub size: u64,
    pub perm: String,
    pub uid: u32,
    pub gid: u32,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub blake3: String,  // Primary hash using BLAKE3
    pub mtime: DateTime<Utc>,
    pub ctime: DateTime<Utc>,
    pub atime: DateTime<Utc>,
    pub inode: u64,
    pub dev: u64,
    pub scanned: bool,
}

/// Complete file entry including path
#[derive(Debug, Clone)]
pub struct FimEntry {
    pub path: PathBuf,
    pub data: FimEntryData,
}

/// FIM Database handle
pub struct FimDb {
    conn: Connection,
    memory_mode: bool,
    transaction_count: usize,
}

impl FimDb {
    /// Initialize FIM database
    /// 
    /// # Arguments
    /// * `memory` - true for in-memory database, false for disk storage
    /// 
    /// # Returns
    /// * `Result<Self>` - Database instance or error
    pub fn init(memory: bool) -> Result<Self> {
        let conn = if memory {
            Connection::open_in_memory()
                .context("Failed to create in-memory database")?
        } else {
            // Use a more descriptive filename
            let db_path = "fim_integrity.db";
            Connection::open(db_path)
                .context("Failed to open database file")?
        };

        // Configure SQLite for performance
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "cache_size", "-64000")?; // 64MB cache
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        
        let db = Self {
            conn,
            memory_mode: memory,
            transaction_count: 0,
        };

        db.create_tables()?;
        db.create_indices()?;
        
        info!("FIM database initialized (memory: {})", memory);
        Ok(db)
    }

    /// Create database tables
    fn create_tables(&self) -> Result<()> {
        // Main file data table
        self.conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS file_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                size INTEGER NOT NULL,
                perm TEXT NOT NULL,
                uid INTEGER NOT NULL,
                gid INTEGER NOT NULL,
                md5 TEXT,
                sha1 TEXT,
                sha256 TEXT,
                blake3 TEXT NOT NULL,
                mtime INTEGER NOT NULL,
                ctime INTEGER NOT NULL,
                atime INTEGER NOT NULL,
                inode INTEGER NOT NULL,
                dev INTEGER NOT NULL,
                scanned INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
            "#,
            [],
        )?;

        // Checksum tracking table for sync operations
        self.conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS sync_info (
                id INTEGER PRIMARY KEY,
                last_sync_id INTEGER NOT NULL DEFAULT 0,
                total_files INTEGER NOT NULL DEFAULT 0,
                last_sync_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
            "#,
            [],
        )?;

        // Initialize sync_info if empty
        self.conn.execute(
            "INSERT OR IGNORE INTO sync_info (id) VALUES (1)",
            [],
        )?;

        Ok(())
    }

    /// Create optimized indices
    fn create_indices(&self) -> Result<()> {
        let indices = [
            "CREATE INDEX IF NOT EXISTS idx_file_path ON file_data(path)",
            "CREATE INDEX IF NOT EXISTS idx_file_inode_dev ON file_data(inode, dev)",
            "CREATE INDEX IF NOT EXISTS idx_file_scanned ON file_data(scanned)",
            "CREATE INDEX IF NOT EXISTS idx_file_mtime ON file_data(mtime)",
            "CREATE INDEX IF NOT EXISTS idx_file_blake3 ON file_data(blake3)",
        ];

        for index_sql in &indices {
            self.conn.execute(index_sql, [])?;
        }

        Ok(())
    }

    /// Set all entries to unscanned state
    pub fn set_all_unscanned(&mut self) -> Result<i32> {
        let updated = self.conn.execute(
            "UPDATE file_data SET scanned = 0",
            [],
        )?;
        
        debug!("Set {} entries to unscanned", updated);
        Ok(FIMDB_OK)
    }

    /// Clean/remove the database
    pub fn clean() -> Result<i32> {
        if Path::new("fim_integrity.db").exists() {
            std::fs::remove_file("fim_integrity.db")
                .context("Failed to remove database file")?;
        }
        Ok(FIMDB_OK)
    }

    /// Begin transaction for batch operations
    pub fn begin_transaction(&mut self) -> Result<()> {
        if self.transaction_count == 0 {
            self.conn.execute("BEGIN IMMEDIATE", [])?;
        }
        self.transaction_count += 1;
        Ok(())
    }

    /// Commit transaction
    pub fn commit_transaction(&mut self) -> Result<()> {
        if self.transaction_count > 0 {
            self.transaction_count -= 1;
            if self.transaction_count == 0 {
                self.conn.execute("COMMIT", [])?;
            }
        }
        Ok(())
    }

    /// Force commit (for periodic commits during long operations)
    pub fn force_commit(&mut self) {
        if self.transaction_count > 0 {
            if let Err(e) = self.conn.execute("COMMIT", []) {
                warn!("Failed to force commit: {}", e);
            } else {
                // Restart transaction
                if let Err(e) = self.conn.execute("BEGIN IMMEDIATE", []) {
                    warn!("Failed to restart transaction: {}", e);
                }
            }
        }
    }

    /// Get file entry by path
    pub fn get_path(&self, file_path: &Path) -> Result<Option<FimEntry>> {
        let path_str = file_path.to_string_lossy();
        
        let entry = self.conn.query_row(
            r#"
            SELECT path, size, perm, uid, gid, md5, sha1, sha256, blake3,
                   mtime, ctime, atime, inode, dev, scanned
            FROM file_data WHERE path = ?1
            "#,
            [&path_str],
            |row| {
                Ok(FimEntry {
                    path: PathBuf::from(row.get::<_, String>(0)?),
                    data: FimEntryData {
                        size: row.get(1)?,
                        perm: row.get(2)?,
                        uid: row.get(3)?,
                        gid: row.get(4)?,
                        md5: row.get(5)?,
                        sha1: row.get(6)?,
                        sha256: row.get(7)?,
                        blake3: row.get(8)?,
                        mtime: DateTime::from_timestamp(row.get::<_, i64>(9)?, 0).unwrap_or_default(),
                        ctime: DateTime::from_timestamp(row.get::<_, i64>(10)?, 0).unwrap_or_default(),
                        atime: DateTime::from_timestamp(row.get::<_, i64>(11)?, 0).unwrap_or_default(),
                        inode: row.get(12)?,
                        dev: row.get(13)?,
                        scanned: row.get::<_, i32>(14)? != 0,
                    },
                })
            }
        ).optional()?;

        Ok(entry)
    }

    /// Check if inode exists
    pub fn get_inode(&self, inode: u64, dev: u64) -> Result<bool> {
        let count: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM file_data WHERE inode = ?1 AND dev = ?2",
            params![inode, dev],
            |row| row.get(0),
        )?;
        
        Ok(count > 0)
    }

    /// Get all paths for a given inode
    pub fn get_paths_from_inode(&self, inode: u64, dev: u64) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT path FROM file_data WHERE inode = ?1 AND dev = ?2"
        )?;
        
        let paths = stmt.query_map(params![inode, dev], |row| {
            Ok(row.get::<_, String>(0)?)
        })?
        .collect::<Result<Vec<_>, _>>()?;
        
        Ok(paths)
    }

    /// Insert or update file entry
    pub fn insert_data(&mut self, file_path: &Path, entry: &FimEntryData) -> Result<i32> {
        let path_str = file_path.to_string_lossy();
        
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO file_data 
            (path, size, perm, uid, gid, md5, sha1, sha256, blake3,
             mtime, ctime, atime, inode, dev, scanned, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, strftime('%s', 'now'))
            "#,
            params![
                path_str,
                entry.size,
                entry.perm,
                entry.uid,
                entry.gid,
                entry.md5,
                entry.sha1,
                entry.sha256,
                entry.blake3,
                entry.mtime.timestamp(),
                entry.ctime.timestamp(),
                entry.atime.timestamp(),
                entry.inode,
                entry.dev,
                entry.scanned as i32,
            ],
        )?;
        
        Ok(FIMDB_OK)
    }

    /// Remove path from database
    pub fn remove_path(&mut self, file_path: &Path) -> Result<i32> {
        let path_str = file_path.to_string_lossy();
        let deleted = self.conn.execute(
            "DELETE FROM file_data WHERE path = ?1",
            [&path_str],
        )?;
        
        debug!("Removed {} entries for path: {}", deleted, path_str);
        Ok(FIMDB_OK)
    }

    /// Delete unscanned entries
    pub fn delete_not_scanned(&mut self) -> Result<i32> {
        let deleted = self.conn.execute(
            "DELETE FROM file_data WHERE scanned = 0",
            [],
        )?;
        
        info!("Deleted {} unscanned entries", deleted);
        Ok(deleted as i32)
    }

    /// Delete entries in path range (alphabetically sorted)
    pub fn delete_range(&mut self, start: &str, top: &str) -> Result<i32> {
        let deleted = self.conn.execute(
            "DELETE FROM file_data WHERE path >= ?1 AND path <= ?2",
            params![start, top],
        )?;
        
        debug!("Deleted {} entries in range {} to {}", deleted, start, top);
        Ok(deleted as i32)
    }

    /// Get count of entries in range
    pub fn get_count_range(&self, start: &str, top: &str) -> Result<i32> {
        let count: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM file_data WHERE path >= ?1 AND path <= ?2",
            params![start, top],
            |row| row.get(0),
        )?;
        
        Ok(count)
    }

    /// Get first or last row path
    pub fn get_row_path(&self, mode: RowMode) -> Result<Option<String>> {
        let sql = match mode {
            RowMode::First => "SELECT path FROM file_data ORDER BY path ASC LIMIT 1",
            RowMode::Last => "SELECT path FROM file_data ORDER BY path DESC LIMIT 1",
        };
        
        let path = self.conn.query_row(sql, [], |row| {
            Ok(row.get::<_, String>(0)?)
        }).optional()?;
        
        Ok(path)
    }

    /// Calculate data checksum for integrity verification
    pub fn get_data_checksum(&self) -> Result<String> {
        let mut hasher = blake3::Hasher::new();
        
        let mut stmt = self.conn.prepare(
            "SELECT blake3 FROM file_data ORDER BY path"
        )?;
        
        let hashes = stmt.query_map([], |row| {
            Ok(row.get::<_, String>(0)?)
        })?;
        
        for hash_result in hashes {
            let hash = hash_result?;
            hasher.update(hash.as_bytes());
        }
        
        Ok(hasher.finalize().to_hex().to_string())
    }

    /// Get database statistics
    pub fn get_stats(&self) -> Result<FimStats> {
        let total_files: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM file_data",
            [],
            |row| row.get(0),
        )?;
        
        let scanned_files: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM file_data WHERE scanned = 1",
            [],
            |row| row.get(0),
        )?;
        
        Ok(FimStats {
            total_files,
            scanned_files,
            unscanned_files: total_files - scanned_files,
        })
    }
}

/// Row selection mode
#[derive(Debug, Clone)]
pub enum RowMode {
    First,
    Last,
}

/// Database statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimStats {
    pub total_files: i32,
    pub scanned_files: i32,
    pub unscanned_files: i32,
}

impl Drop for FimDb {
    fn drop(&mut self) {
        // Ensure any pending transactions are committed
        if self.transaction_count > 0 {
            let _ = self.conn.execute("COMMIT", []);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_database_init() -> Result<()> {
        let db = FimDb::init(true)?;
        assert!(db.memory_mode);
        Ok(())
    }

    #[test]
    fn test_file_operations() -> Result<()> {
        let mut db = FimDb::init(true)?;
        let test_path = PathBuf::from("/test/file.txt");
        
        let entry_data = FimEntryData {
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
        };
        
        // Insert entry
        db.insert_data(&test_path, &entry_data)?;
        
        // Retrieve entry
        let retrieved = db.get_path(&test_path)?;
        assert!(retrieved.is_some());
        
        let entry = retrieved.unwrap();
        assert_eq!(entry.path, test_path);
        assert_eq!(entry.data.size, 1024);
        assert_eq!(entry.data.blake3, "test_hash");
        
        Ok(())
    }
}