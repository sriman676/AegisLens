package com.aegislens.db;

import java.sql.SQLException;
import java.time.Instant;
import java.util.List;

/**
 * Append-only audit trail of analyst actions (block IP, mark false positive, change a rule, run the sandbox).
 */
public class AuditLogRepository extends BaseRepository<AuditEntry, Long> {

    public AuditLogRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "audit_log";
    }

    /** Records an action now and returns its id. */
    public long append(String actor, String action, String detail) throws SQLException {
        return insert("INSERT INTO audit_log (actor, action, detail, at) VALUES (?, ?, ?, ?)", ps -> {
            ps.setString(1, actor);
            ps.setString(2, action);
            ps.setString(3, detail);
            ps.setString(4, iso(Instant.now()));
        });
    }

    /** The newest n entries, newest first. */
    public List<AuditEntry> recent(int n) throws SQLException {
        return queryList("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", ps -> ps.setInt(1, n),
                rs -> new AuditEntry(rs.getLong("id"), rs.getString("actor"), rs.getString("action"),
                        rs.getString("detail"), instant(rs, "at")));
    }
}
