-- Optional full-text search (D9). Loaded after schema.sql inside try/catch: if this SQLite build has no FTS5,
-- the app falls back to LIKE search. Same rules as schema.sql: statements are separated by lines "-- GO".
CREATE VIRTUAL TABLE IF NOT EXISTS finding_fts USING fts5(description, target, content='finding', content_rowid='id');
-- GO

CREATE TRIGGER IF NOT EXISTS trg_fts_insert AFTER INSERT ON finding
BEGIN
    INSERT INTO finding_fts (rowid, description, target) VALUES (NEW.id, NEW.description, NEW.target);
END;
-- GO

CREATE TRIGGER IF NOT EXISTS trg_fts_delete AFTER DELETE ON finding
BEGIN
    INSERT INTO finding_fts (finding_fts, rowid, description, target) VALUES ('delete', OLD.id, OLD.description, OLD.target);
END;
-- GO

CREATE TRIGGER IF NOT EXISTS trg_fts_update AFTER UPDATE OF description, target ON finding
BEGIN
    INSERT INTO finding_fts (finding_fts, rowid, description, target) VALUES ('delete', OLD.id, OLD.description, OLD.target);
    INSERT INTO finding_fts (rowid, description, target) VALUES (NEW.id, NEW.description, NEW.target);
END;
-- GO
