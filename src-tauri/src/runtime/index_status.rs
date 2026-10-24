use crate::models::{now, AppError, Result};
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension};
use std::{
    path::Path,
    time::{Duration, Instant},
};

/// Read only this project's index, without CLI startup, migrations, repairs or
/// source-tree traversal. A transaction keeps the marker and counts consistent
/// with each other while an external CodeGraph writer is active.
pub(super) fn read(root: &Path) -> Result<Option<serde_json::Value>> {
    read_with_budget(root, Duration::from_secs(5))
}

fn read_with_budget(root: &Path, budget: Duration) -> Result<Option<serde_json::Value>> {
    if !root.is_dir() {
        return Err(AppError::new("PROJECT_MISSING", "项目目录不存在"));
    }
    let path = root.join(".codegraph/codegraph.db");
    match path.try_exists() {
        Ok(false) => return Ok(None),
        Err(e) => return Err(AppError::new("INDEX_STATUS_FAILED", e)),
        Ok(true) => (),
    }
    let started = Instant::now();
    let mut db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(database_error)?;
    db.busy_timeout(budget).map_err(database_error)?;
    // Unlike an async timeout around spawn_blocking, this actually interrupts
    // expensive SQLite statements instead of leaving background readers running.
    db.progress_handler(1000, Some(move || started.elapsed() >= budget));
    let tx = db.transaction().map_err(database_error)?;
    let state: Option<String> = tx
        .query_row(
            "SELECT value FROM project_metadata WHERE key = 'index_state'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_error)?;
    if state.as_deref() != Some("complete") {
        return Err(AppError::new(
            "INDEX_NOT_READY",
            "索引未完成，或索引项目路径不匹配",
        ));
    }
    let (files, nodes, edges): (i64, i64, i64) = tx.query_row(
        "SELECT (SELECT COUNT(*) FROM files), (SELECT COUNT(*) FROM nodes), (SELECT COUNT(*) FROM edges)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(database_error)?;
    tx.commit().map_err(database_error)?;
    Ok(Some(serde_json::json!({
        "fileCount": files, "nodeCount": nodes, "edgeCount": edges, "checkedAt": now()
    })))
}

fn database_error(error: rusqlite::Error) -> AppError {
    match error.sqlite_error_code() {
        Some(
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked | ErrorCode::OperationInterrupted,
        ) => AppError::new("INDEX_STATUS_TIMEOUT", "读取索引超时"),
        _ => AppError::new("INDEX_STATUS_FAILED", error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = "
        CREATE TABLE project_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO project_metadata VALUES('index_state', 'complete');
        INSERT INTO project_metadata VALUES('indexed_at_commit', '');
        INSERT INTO project_metadata VALUES('indexed_dirty_paths', '');
        CREATE TABLE files(path TEXT);
        CREATE TABLE nodes(id TEXT);
        CREATE TABLE edges(id INTEGER);
        INSERT INTO files VALUES('removed.go');
        INSERT INTO nodes VALUES('a'), ('b');
        INSERT INTO edges VALUES(1);";

    fn fixture() -> (tempfile::TempDir, Connection) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".codegraph")).unwrap();
        let db = Connection::open(root.path().join(".codegraph/codegraph.db")).unwrap();
        db.execute_batch(SCHEMA).unwrap();
        (root, db)
    }

    #[test]
    fn reads_persisted_counts_without_git_stamps_or_source_files_and_does_not_write() {
        let (root, db) = fixture();
        drop(db);
        let path = root.path().join(".codegraph/codegraph.db");
        let before = std::fs::read(&path).unwrap();
        let stats = read(root.path()).unwrap().unwrap();
        assert_eq!(stats["fileCount"], 1);
        assert_eq!(stats["nodeCount"], 2);
        assert_eq!(stats["edgeCount"], 1);
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn missing_index_is_not_created_and_parent_index_is_not_borrowed() {
        let (root, _db) = fixture();
        let child = root.path().join("child");
        std::fs::create_dir_all(child.join(".codegraph")).unwrap();
        assert!(read(&child).unwrap().is_none());
        assert!(!child.join(".codegraph/codegraph.db").exists());
        assert_eq!(
            read(&root.path().join("missing")).unwrap_err().code,
            "PROJECT_MISSING"
        );
    }

    #[test]
    fn incomplete_and_unknown_states_are_not_ready() {
        let (root, db) = fixture();
        for state in ["indexing", "partial", "failed", "future-state"] {
            db.execute(
                "UPDATE project_metadata SET value=?1 WHERE key='index_state'",
                [state],
            )
            .unwrap();
            assert_eq!(read(root.path()).unwrap_err().code, "INDEX_NOT_READY");
        }
        db.execute("DELETE FROM project_metadata WHERE key='index_state'", [])
            .unwrap();
        assert_eq!(read(root.path()).unwrap_err().code, "INDEX_NOT_READY");
    }

    #[test]
    fn corrupt_or_incompatible_database_is_rejected_without_repair() {
        let (root, db) = fixture();
        db.execute("DROP TABLE nodes", []).unwrap();
        assert_eq!(read(root.path()).unwrap_err().code, "INDEX_STATUS_FAILED");
        drop(db);
        let path = root.path().join(".codegraph/codegraph.db");
        std::fs::write(&path, b"not a database").unwrap();
        assert_eq!(read(root.path()).unwrap_err().code, "INDEX_STATUS_FAILED");
        assert_eq!(std::fs::read(path).unwrap(), b"not a database");
    }

    #[test]
    fn wal_reader_sees_committed_state_while_writer_is_active() {
        let (root, db) = fixture();
        db.execute_batch("PRAGMA journal_mode=WAL; BEGIN IMMEDIATE; UPDATE project_metadata SET value='indexing' WHERE key='index_state'; DELETE FROM nodes;").unwrap();
        assert_eq!(read(root.path()).unwrap().unwrap()["nodeCount"], 2);
        db.execute_batch("COMMIT").unwrap();
        assert_eq!(read(root.path()).unwrap_err().code, "INDEX_NOT_READY");
    }

    #[test]
    fn exclusive_lock_times_out_and_can_be_retried() {
        let (root, db) = fixture();
        db.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let started = Instant::now();
        assert_eq!(
            read_with_budget(root.path(), Duration::from_millis(50))
                .unwrap_err()
                .code,
            "INDEX_STATUS_TIMEOUT"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        db.execute_batch("ROLLBACK").unwrap();
        assert!(read(root.path()).unwrap().is_some());
    }

    #[test]
    fn expensive_count_is_interrupted_instead_of_leaving_a_background_query() {
        let (root, db) = fixture();
        db.execute_batch("DROP TABLE nodes; CREATE VIEW nodes AS WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT x FROM n;").unwrap();
        let started = Instant::now();
        assert_eq!(
            read_with_budget(root.path(), Duration::from_millis(50))
                .unwrap_err()
                .code,
            "INDEX_STATUS_TIMEOUT"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    #[ignore = "requires CODEGRAPH_STATUS_TEST_PROJECT pointing to a real indexed project"]
    fn reads_real_project_without_scanning_sources() {
        let root = std::env::var("CODEGRAPH_STATUS_TEST_PROJECT").unwrap();
        let started = Instant::now();
        let stats = read(Path::new(&root)).unwrap().unwrap();
        println!("Index readiness: {stats}; elapsed: {:?}", started.elapsed());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
