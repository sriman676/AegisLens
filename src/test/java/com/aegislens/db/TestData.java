package com.aegislens.db;

import com.aegislens.core.Finding;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/** Small helpers shared by the repository tests. */
final class TestData {

    private TestData() {
    }

    /** The first column of the first row of a query, as text (null if there is no row). */
    static String scalar(Connection c, String sql) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
            return rs.next() ? rs.getString(1) : null;
        }
    }

    /** Saves one finding in a new session and returns its id. */
    static long savedFinding(Database db) throws SQLException {
        long session = new ScanSessionRepository(db).begin("INTRUSION", "auth.log");
        Finding f = new Finding("ssh", "203.0.113.45", "NET-001", 72, "7 failed logins");
        f.setSessionId(session);
        new FindingRepository(db).save(f);
        return f.id();
    }
}
