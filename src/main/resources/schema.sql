-- AegisLens SQLite schema, version 5. v3 added views, triggers and the finding_counts table, v4 covering indexes, v5 the HOST module.
-- Rules for this file: whole-line "--" comments only, and every statement is followed by a line that is exactly "-- GO" (the loader splits there, so triggers with ";" inside their BEGIN ... END body work).
PRAGMA foreign_keys = ON;
-- GO

CREATE TABLE IF NOT EXISTS scan_session (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    module      TEXT NOT NULL CHECK (module IN ('MALWARE','INTRUSION','WEB','SANDBOX','HOST')),
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'RUNNING' CHECK (status IN ('RUNNING','DONE','FAILED'))
);
-- GO

CREATE TABLE IF NOT EXISTS finding (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES scan_session(id) ON DELETE CASCADE,
    source      TEXT NOT NULL,
    target      TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    score       INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    description TEXT NOT NULL,
    evidence    TEXT,
    status      TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','FALSE_POSITIVE','RESOLVED')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
-- GO
CREATE INDEX IF NOT EXISTS idx_finding_sev ON finding(severity, created_at);
-- GO
-- Covering indexes (v4): every column a report or dashboard query reads is in the index, so GROUP BY target / rule /
-- day reads the small index instead of the wide table rows (descriptions, evidence). Measured on 1 M findings.
CREATE INDEX IF NOT EXISTS idx_finding_target_stats ON finding(target, status, session_id, score, created_at);
-- GO
CREATE INDEX IF NOT EXISTS idx_finding_time ON finding(created_at, severity, status);
-- GO
-- Dashboard filters (status <> 'FALSE_POSITIVE' GROUP BY severity) and per-rule history
CREATE INDEX IF NOT EXISTS idx_finding_status_sev ON finding(status, severity);
-- GO
CREATE INDEX IF NOT EXISTS idx_finding_rule_stats ON finding(rule_id, created_at, status, score);
-- GO

CREATE TABLE IF NOT EXISTS file_report (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES scan_session(id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    file_type   TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    md5         TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    entropy     REAL NOT NULL,
    risk_score  INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    scanned_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
-- GO
CREATE INDEX IF NOT EXISTS idx_file_sha ON file_report(sha256);
-- GO

CREATE TABLE IF NOT EXISTS ioc (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL CHECK (kind IN ('HASH','IP','CIDR','DOMAIN','URL','STRING','API')),
    value       TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'manual',
    note        TEXT,
    added_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (kind, value)
);
-- GO
CREATE INDEX IF NOT EXISTS idx_ioc_source ON ioc(source);
-- GO

CREATE TABLE IF NOT EXISTS rule (
    id          TEXT PRIMARY KEY,
    module      TEXT NOT NULL,
    name        TEXT NOT NULL,
    pattern     TEXT,
    threshold   REAL,
    severity    TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1
);
-- GO

CREATE TABLE IF NOT EXISTS blocked_ip (
    ip          TEXT PRIMARY KEY,
    reason      TEXT,
    blocked_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
-- GO

CREATE TABLE IF NOT EXISTS ai_explanation (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    explanation TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (finding_id, provider)
);
-- GO

CREATE TABLE IF NOT EXISTS setting (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);
-- GO

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT,
    at          TEXT NOT NULL DEFAULT (datetime('now'))
);
-- GO

CREATE TABLE IF NOT EXISTS log_offset (
    path        TEXT PRIMARY KEY,
    offset      INTEGER NOT NULL,
    fingerprint TEXT,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
-- GO

CREATE TABLE IF NOT EXISTS feed_state (
    name          TEXT PRIMARY KEY,
    url           TEXT NOT NULL,
    last_checked  TEXT,
    last_success  TEXT,
    etag          TEXT,
    last_modified TEXT,
    entries       INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT
);
-- GO

CREATE TABLE IF NOT EXISTS vt_cache (
    sha256      TEXT PRIMARY KEY,
    known       INTEGER NOT NULL,
    malicious   INTEGER NOT NULL DEFAULT 0,
    suspicious  INTEGER NOT NULL DEFAULT 0,
    total       INTEGER NOT NULL DEFAULT 0,
    checked_at  TEXT NOT NULL
);
-- GO

CREATE TABLE IF NOT EXISTS quarantine (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    vault_path    TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    reason        TEXT,
    at            TEXT NOT NULL DEFAULT (datetime('now')),
    restored      INTEGER NOT NULL DEFAULT 0
);
-- GO

-- Seed rules (thresholds are read by the detectors; edit them in the Settings screen or with SQL)
INSERT OR IGNORE INTO rule (id, module, name, pattern, threshold, severity) VALUES
 ('NET-001','INTRUSION','SSH brute force', 'Failed password', 5, 'HIGH'),
 ('NET-002','INTRUSION','Path or port scan', NULL, 15, 'MEDIUM'),
 ('NET-003','INTRUSION','Odd-hour login', NULL, NULL, 'LOW'),
 ('NET-004','INTRUSION','Request-rate anomaly (z-score)', NULL, 3.0, 'MEDIUM'),
 ('NET-005','INTRUSION','Address on a threat-intelligence list', NULL, NULL, 'HIGH'),
 ('NET-006','INTRUSION','Attack-tool user agent', 'sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wpscan|hydra', NULL, 'MEDIUM'),
 ('NET-007','INTRUSION','Password spraying (many users, one address)', NULL, 5, 'HIGH'),
 ('MAL-001','MALWARE','High entropy (packed)', NULL, 7.2, 'MEDIUM'),
 ('MAL-002','MALWARE','Suspicious imported API', 'VirtualAlloc|WriteProcessMemory|CreateRemoteThread', NULL, 'HIGH'),
 ('MAL-003','MALWARE','Embedded URL/IP', 'https?://', NULL, 'LOW'),
 ('MAL-004','MALWARE','Known-bad file hash', NULL, NULL, 'CRITICAL'),
 ('MAL-005','MALWARE','VirusTotal detections', NULL, 1, 'HIGH'),
 ('MAL-006','MALWARE','Suspicious file structure', NULL, NULL, 'MEDIUM'),
 ('WEB-001','WEB','Lookalike or deceptive domain', NULL, 2, 'HIGH'),
 ('WEB-002','WEB','Injection pattern in URL', '(?i)(union\s+select|or\s+1=1|''\s?--|--\s?$)', NULL, 'HIGH'),
 ('WEB-003','WEB','Missing security header', NULL, NULL, 'LOW'),
 ('WEB-004','WEB','Domain or URL on a threat-intelligence list', NULL, NULL, 'CRITICAL'),
 ('WEB-005','WEB','Suspicious page content (HTML)', NULL, NULL, 'MEDIUM'),
 ('HOST-001','HOST','Suspicious PowerShell (Sysmon)', NULL, NULL, 'HIGH'),
 ('HOST-002','HOST','Windows tool misused to download or run code (Sysmon)', NULL, NULL, 'HIGH'),
 ('HOST-003','HOST','Program started from a user folder (Sysmon)', NULL, NULL, 'MEDIUM'),
 ('HOST-004','HOST','Document app or browser started a shell (Sysmon)', NULL, NULL, 'HIGH'),
 ('HOST-005','HOST','Connection to a threat-list address (Sysmon)', NULL, NULL, 'CRITICAL'),
 ('HOST-006','HOST','DNS lookup of a listed or look-alike domain (Sysmon)', NULL, NULL, 'HIGH'),
 ('HOST-007','HOST','File put in a Startup folder (Sysmon)', NULL, NULL, 'HIGH'),
 ('HOST-008','HOST','Run/RunOnce registry autostart (Sysmon)', NULL, NULL, 'HIGH'),
 ('HOST-009','HOST','Service program set (Sysmon)', NULL, NULL, 'MEDIUM');
-- GO

-- R13 evaluation (2026-10-31): the old WEB-002 default matched any "--" (for example /blog/2026--recap). Files that
-- still have the old default get the new one; a pattern you changed yourself is left alone.
UPDATE rule SET pattern = '(?i)(union\s+select|or\s+1=1|''\s?--|--\s?$)'
WHERE id = 'WEB-002' AND pattern = '(?i)(union\s+select|or\s+1=1|--)';
-- GO

-- Seed IOC: SHA-256 of the standard EICAR antivirus test file (harmless test string)
INSERT OR IGNORE INTO ioc (kind, value, source, note) VALUES ('HASH', '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'builtin', 'EICAR antivirus test file');
-- GO

-- ===== Version 3 (R18): views, summary table and triggers =====
-- D1: one row per finding with its scan session and rule (JOIN + LEFT JOIN)
CREATE VIEW IF NOT EXISTS v_finding_detail AS
SELECT f.id, f.created_at, f.severity, f.score, f.rule_id, r.name AS rule_name, s.module, f.source, f.target,
       f.description, f.status, f.session_id, s.target AS session_target, f.evidence
FROM finding f
JOIN scan_session s ON s.id = f.session_id
LEFT JOIN rule r ON r.id = f.rule_id;
-- GO

-- D2: findings per day, severity and status (created_at is ISO text, so its first 10 characters are the UTC day)
CREATE VIEW IF NOT EXISTS v_daily_counts AS
SELECT substr(created_at, 1, 10) AS day, severity, status, COUNT(*) AS n
FROM finding
GROUP BY substr(created_at, 1, 10), severity, status;
-- GO

-- Dashboard counts kept up to date by triggers, so the dashboard reads a few rows instead of counting millions
CREATE TABLE IF NOT EXISTS finding_counts (
    severity    TEXT NOT NULL,
    status      TEXT NOT NULL,
    n           INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (severity, status)
);
-- GO

CREATE TRIGGER IF NOT EXISTS trg_counts_insert AFTER INSERT ON finding
BEGIN
    INSERT INTO finding_counts (severity, status, n) VALUES (NEW.severity, NEW.status, 1)
        ON CONFLICT (severity, status) DO UPDATE SET n = n + 1;
END;
-- GO

CREATE TRIGGER IF NOT EXISTS trg_counts_delete AFTER DELETE ON finding
BEGIN
    UPDATE finding_counts SET n = n - 1 WHERE severity = OLD.severity AND status = OLD.status;
END;
-- GO

CREATE TRIGGER IF NOT EXISTS trg_counts_update AFTER UPDATE OF severity, status ON finding
WHEN OLD.severity <> NEW.severity OR OLD.status <> NEW.status
BEGIN
    UPDATE finding_counts SET n = n - 1 WHERE severity = OLD.severity AND status = OLD.status;
    INSERT INTO finding_counts (severity, status, n) VALUES (NEW.severity, NEW.status, 1)
        ON CONFLICT (severity, status) DO UPDATE SET n = n + 1;
END;
-- GO

-- D6: every status change is written to the audit log by the database itself
CREATE TRIGGER IF NOT EXISTS trg_finding_status_audit AFTER UPDATE OF status ON finding
WHEN OLD.status <> NEW.status
BEGIN
    INSERT INTO audit_log (actor, action, detail, at)
    VALUES ('trigger', 'STATUS_CHANGE', 'finding ' || NEW.id || ': ' || OLD.status || ' -> ' || NEW.status,
            strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
END;
-- GO

-- D7: a scan session that still has OPEN findings cannot be deleted (resolve or dismiss them first)
CREATE TRIGGER IF NOT EXISTS trg_session_delete_guard BEFORE DELETE ON scan_session
WHEN EXISTS (SELECT 1 FROM finding WHERE session_id = OLD.id AND status = 'OPEN')
BEGIN
    SELECT RAISE(ABORT, 'scan session still has OPEN findings: resolve them first');
END;
-- GO

-- For the guard above and for joins from scan_session to finding
CREATE INDEX IF NOT EXISTS idx_finding_session_stats ON finding(session_id, status, severity);
-- GO
-- D5/D12: "target IN (SELECT value FROM ioc)" and the EXISTS check look IOCs up by value
CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc(value);
-- GO
