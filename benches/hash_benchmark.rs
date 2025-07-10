//! Performance benchmarks for Rusty FIM
//! 
//! These benchmarks measure the performance of core FIM operations:
//! - File hashing with different algorithms and file sizes
//! - Database operations (insert, query, update)
//! - Filesystem scanning performance
//! - Real-time event processing throughput

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rusty_fim::hasher::{FileHasher, HashConfig};
use rusty_fim::database::{FimDb, FimEntryData};
use rusty_fim::fim::{FimEngine, FimConfig};

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tempfile::{tempdir, NamedTempFile};
use chrono::Utc;

/// Benchmark file hashing performance across different algorithms and file sizes
fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");
    
    // Test different file sizes
    let sizes = vec![
        ("1KB", 1024),
        ("10KB", 10 * 1024),
        ("100KB", 100 * 1024),
        ("1MB", 1024 * 1024),
        ("10MB", 10 * 1024 * 1024),
        ("100MB", 100 * 1024 * 1024),
    ];
    
    for (size_name, size_bytes) in sizes {
        group.throughput(Throughput::Bytes(size_bytes as u64));
        
        // Create test file
        let temp_file = create_test_file(size_bytes);
        
        // Benchmark BLAKE3 (primary algorithm)
        let blake3_hasher = FileHasher::blake3_only();
        group.bench_with_input(
            BenchmarkId::new("blake3", size_name),
            &temp_file,
            |b, file| {
                b.iter(|| {
                    blake3_hasher.hash_file(black_box(file.path())).unwrap()
                });
            },
        );
        
        // Benchmark BLAKE3 with parallel processing (for larger files)
        if size_bytes >= 1024 * 1024 {
            let parallel_hasher = FileHasher::new(HashConfig {
                use_blake3: true,
                parallel_threshold: 64 * 1024, // Lower threshold for benchmarking
                ..Default::default()
            });
            group.bench_with_input(
                BenchmarkId::new("blake3_parallel", size_name),
                &temp_file,
                |b, file| {
                    b.iter(|| {
                        parallel_hasher.hash_file(black_box(file.path())).unwrap()
                    });
                },
            );
        }
        
        // Benchmark SHA-256 for comparison
        let sha256_hasher = FileHasher::new(HashConfig {
            use_blake3: false,
            use_sha256: true,
            ..Default::default()
        });
        group.bench_with_input(
            BenchmarkId::new("sha256", size_name),
            &temp_file,
            |b, file| {
                b.iter(|| {
                    sha256_hasher.hash_file(black_box(file.path())).unwrap()
                });
            },
        );
        
        // Benchmark all algorithms together
        let all_hasher = FileHasher::all_algorithms();
        group.bench_with_input(
            BenchmarkId::new("all_algorithms", size_name),
            &temp_file,
            |b, file| {
                b.iter(|| {
                    all_hasher.hash_file(black_box(file.path())).unwrap()
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark database operations
fn bench_database(c: &mut Criterion) {
    let mut group = c.benchmark_group("database");
    
    // Create in-memory database for consistent benchmarking
    let mut db = FimDb::init(true).unwrap();
    
    // Benchmark single insert
    group.bench_function("insert_single", |b| {
        let mut counter = 0;
        b.iter(|| {
            let entry_data = create_test_entry_data(counter);
            let path = PathBuf::from(format!("/test/file_{}", counter));
            db.insert_data(&path, &entry_data).unwrap();
            counter += 1;
        });
    });
    
    // Prepare data for bulk operations
    let test_entries: Vec<_> = (0..1000)
        .map(|i| {
            let path = PathBuf::from(format!("/test/bulk_{}", i));
            let data = create_test_entry_data(i);
            (path, data)
        })
        .collect();
    
    // Benchmark bulk insert with transaction
    group.bench_function("insert_bulk_1000", |b| {
        b.iter(|| {
            let mut db = FimDb::init(true).unwrap();
            db.begin_transaction().unwrap();
            
            for (path, data) in &test_entries {
                db.insert_data(path, data).unwrap();
            }
            
            db.commit_transaction().unwrap();
        });
    });
    
    // Setup database with test data for query benchmarks
    let mut query_db = FimDb::init(true).unwrap();
    query_db.begin_transaction().unwrap();
    for (path, data) in &test_entries {
        query_db.insert_data(path, data).unwrap();
    }
    query_db.commit_transaction().unwrap();
    
    // Benchmark path lookup
    group.bench_function("query_by_path", |b| {
        b.iter(|| {
            let path = &test_entries[black_box(500)].0;
            query_db.get_path(path).unwrap()
        });
    });
    
    // Benchmark inode lookup
    group.bench_function("query_by_inode", |b| {
        b.iter(|| {
            let inode = black_box(12345);
            let dev = black_box(2049);
            query_db.get_inode(inode, dev).unwrap()
        });
    });
    
    // Benchmark range count
    group.bench_function("count_range", |b| {
        b.iter(|| {
            query_db.get_count_range(
                black_box("/test/bulk_100"),
                black_box("/test/bulk_200")
            ).unwrap()
        });
    });
    
    // Benchmark checksum calculation
    group.bench_function("data_checksum", |b| {
        b.iter(|| {
            query_db.get_data_checksum().unwrap()
        });
    });
    
    group.finish();
}

/// Benchmark filesystem scanning operations
fn bench_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanning");
    
    // Create temporary directory with test files
    let temp_dir = tempdir().unwrap();
    let file_counts = vec![10, 100, 1000];
    
    for count in file_counts {
        // Create test files
        for i in 0..count {
            let file_path = temp_dir.path().join(format!("testfile_{:04}.txt", i));
            let mut file = fs::File::create(&file_path).unwrap();
            writeln!(file, "Test content for file {}", i).unwrap();
        }
        
        // Benchmark baseline scan
        group.bench_with_input(
            BenchmarkId::new("baseline_scan", count),
            &count,
            |b, _| {
                b.iter(|| {
                    let config = FimConfig {
                        monitor_paths: vec![temp_dir.path().to_path_buf()],
                        memory_database: true,
                        enable_realtime: false,
                        ..Default::default()
                    };
                    
                    let mut engine = FimEngine::new(config).unwrap();
                    engine.start().unwrap();
                    let results = engine.baseline_scan().unwrap();
                    black_box(results);
                });
            },
        );
        
        // Benchmark incremental scan
        let config = FimConfig {
            monitor_paths: vec![temp_dir.path().to_path_buf()],
            memory_database: true,
            enable_realtime: false,
            ..Default::default()
        };
        let mut baseline_engine = FimEngine::new(config.clone()).unwrap();
        baseline_engine.start().unwrap();
        baseline_engine.baseline_scan().unwrap();
        
        group.bench_with_input(
            BenchmarkId::new("incremental_scan", count),
            &count,
            |b, _| {
                b.iter(|| {
                    let mut engine = FimEngine::new(config.clone()).unwrap();
                    engine.start().unwrap();
                    let results = engine.incremental_scan().unwrap();
                    black_box(results);
                });
            },
        );
        
        // Cleanup for next iteration
        for i in 0..count {
            let file_path = temp_dir.path().join(format!("testfile_{:04}.txt", i));
            let _ = fs::remove_file(file_path);
        }
    }
    
    group.finish();
}

/// Benchmark parallel file processing
fn bench_parallel_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_processing");
    
    // Create test files
    let temp_dir = tempdir().unwrap();
    let file_count = 1000;
    let files: Vec<_> = (0..file_count)
        .map(|i| {
            let file_path = temp_dir.path().join(format!("parallel_test_{:04}.txt", i));
            let mut file = fs::File::create(&file_path).unwrap();
            writeln!(file, "Parallel test content for file {}", i).unwrap();
            file_path
        })
        .collect();
    
    let hasher = FileHasher::blake3_only();
    
    // Sequential processing
    group.bench_function("sequential_1000_files", |b| {
        b.iter(|| {
            for file_path in &files {
                let _hash = hasher.hash_file(black_box(file_path)).unwrap();
            }
        });
    });
    
    // Parallel processing
    group.bench_function("parallel_1000_files", |b| {
        b.iter(|| {
            let _hashes = hasher.hash_files_parallel(black_box(&files));
        });
    });
    
    group.finish();
}

/// Benchmark memory usage patterns
fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");
    
    // Test memory vs disk database performance
    group.bench_function("memory_database", |b| {
        b.iter(|| {
            let mut db = FimDb::init(true).unwrap();
            db.begin_transaction().unwrap();
            
            for i in 0..1000 {
                let entry_data = create_test_entry_data(i);
                let path = PathBuf::from(format!("/memory/test_{}", i));
                db.insert_data(&path, &entry_data).unwrap();
            }
            
            db.commit_transaction().unwrap();
            black_box(db);
        });
    });
    
    group.bench_function("disk_database", |b| {
        b.iter(|| {
            let mut db = FimDb::init(false).unwrap();
            db.begin_transaction().unwrap();
            
            for i in 0..1000 {
                let entry_data = create_test_entry_data(i);
                let path = PathBuf::from(format!("/disk/test_{}", i));
                db.insert_data(&path, &entry_data).unwrap();
            }
            
            db.commit_transaction().unwrap();
            black_box(db);
        });
    });
    
    group.finish();
}

/// Helper function to create test files of specified size
fn create_test_file(size_bytes: usize) -> NamedTempFile {
    let mut temp_file = NamedTempFile::new().unwrap();
    
    // Create content pattern
    let pattern = b"0123456789abcdef";
    let mut written = 0;
    
    while written < size_bytes {
        let to_write = std::cmp::min(pattern.len(), size_bytes - written);
        temp_file.write_all(&pattern[..to_write]).unwrap();
        written += to_write;
    }
    
    temp_file.flush().unwrap();
    temp_file
}

/// Helper function to create test entry data
fn create_test_entry_data(index: usize) -> FimEntryData {
    FimEntryData {
        size: 1024 + (index as u64),
        perm: "644".to_string(),
        uid: 1000,
        gid: 1000,
        md5: Some(format!("md5_hash_{:08x}", index)),
        sha1: Some(format!("sha1_hash_{:08x}", index)),
        sha256: Some(format!("sha256_hash_{:08x}", index)),
        blake3: format!("blake3_hash_{:08x}", index),
        mtime: Utc::now(),
        ctime: Utc::now(),
        atime: Utc::now(),
        inode: 12345 + (index as u64),
        dev: 2049,
        scanned: true,
    }
}

criterion_group!(
    benches,
    bench_hashing,
    bench_database,
    bench_scanning,
    bench_parallel_processing,
    bench_memory_usage
);

criterion_main!(benches);

#[cfg(test)]
mod benchmark_tests {
    use super::*;
    
    #[test]
    fn test_create_test_file() {
        let temp_file = create_test_file(1024);
        let metadata = fs::metadata(temp_file.path()).unwrap();
        assert_eq!(metadata.len(), 1024);
    }
    
    #[test]
    fn test_create_test_entry_data() {
        let entry = create_test_entry_data(42);
        assert_eq!(entry.size, 1024 + 42);
        assert_eq!(entry.inode, 12345 + 42);
        assert!(entry.blake3.contains("42"));
    }
    
    #[test]
    fn benchmark_sanity_check() {
        // Ensure benchmark functions don't panic
        let temp_file = create_test_file(1024);
        let hasher = FileHasher::blake3_only();
        let _result = hasher.hash_file(temp_file.path()).unwrap();
        
        let mut db = FimDb::init(true).unwrap();
        let entry_data = create_test_entry_data(0);
        let path = PathBuf::from("/test/sanity");
        db.insert_data(&path, &entry_data).unwrap();
    }
}