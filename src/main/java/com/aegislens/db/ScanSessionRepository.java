package com.aegislens.db;

import java.sql.PreparedStatement;
import java.sql.SQLException;

/** Creates and closes scan sessions. Every finding and file report belongs to one session. */
public class ScanSessionRepository extends BaseRepository<Long, Long> {

    public ScanSessionRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "scan_session";
    }

    /** Starts a session for MALWARE, INTRUSION, WEB, SANDBOX or HOST and returns its id. */
    public long begin(String module, String target) throws SQLException {
        return db.locked(c -> {
            try (PreparedStatement ps = c.prepareStatement("INSERT INTO scan_session (module, target) VALUES (?, ?)")) {
                ps.setString(1, module);
                ps.setString(2, target);
                ps.executeUpdate();
            }
            return Database.lastInsertId(c);
        });
    }

    /** Deletes a session; its findings and file reports go with it (ON DELETE CASCADE in schema.sql). */
    public void delete(long sessionId) throws SQLException {
        update("DELETE FROM scan_session WHERE id = ?", ps -> ps.setLong(1, sessionId));
    }

    /** Marks a session DONE or FAILED. */
    public void finish(long sessionId, boolean success) throws SQLException {
        db.locked(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE scan_session SET status = ?, finished_at = datetime('now') WHERE id = ?")) {
                ps.setString(1, success ? "DONE" : "FAILED");
                ps.setLong(2, sessionId);
                ps.executeUpdate();
            }
            return null;
        });
    }
}
