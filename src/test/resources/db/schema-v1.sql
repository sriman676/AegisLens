-- Test fixture: a version-1 database as an older release would have left it (finding has no status column yet).
-- Built for the migration test. The real v1 file was never released, so this models the S3 failure case.
CREATE TABLE scan_session (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    module      TEXT NOT NULL,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'RUNNING'
);
CREATE TABLE finding (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES scan_session(id) ON DELETE CASCADE,
    source      TEXT NOT NULL,
    target      TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    score       INTEGER NOT NULL,
    description TEXT NOT NULL,
    evidence    TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO scan_session (id, module, target) VALUES (1, 'INTRUSION', 'auth.log');
INSERT INTO finding (session_id, source, target, rule_id, severity, score, description, evidence, created_at)
 VALUES (1, 'ssh', '203.0.113.45', 'NET-001', 'HIGH', 72, 'old finding', '{}', '2026-01-02T03:04:05Z');
PRAGMA user_version = 1;
