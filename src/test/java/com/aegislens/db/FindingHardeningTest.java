package com.aegislens.db;

import com.aegislens.core.Finding;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Batching, paging, indexes, cascade, UTC timestamps and SQL injection safety. */
class FindingHardeningTest {

    @Test
    void saveAllWritesEverythingOrNothing() throws SQLException {
        try (Database db = Database.inMemory()) {
            long session = new ScanSessionRepository(db).begin("INTRUSION", "x");
            FindingRepository repo = new FindingRepository(db);
            List<Finding> batch = findings(session, 50);
            repo.saveAll(batch);
            assertEquals(50, repo.count());
            assertTrue(batch.stream().allMatch(f -> f.id() > 0), "ids are filled in");

            List<Finding> broken = findings(session, 3);
            broken.get(2).setStatus("NOT_A_STATUS");                 // violates the CHECK constraint
            assertThrows(SQLException.class, () -> repo.saveAll(broken));
            assertEquals(50, repo.count(), "the failed batch left nothing behind");
        }
    }

    @Test
    void keysetPagingWalksTheWholeTableNewestFirst() throws SQLException {
        try (Database db = Database.inMemory()) {
            long session = new ScanSessionRepository(db).begin("INTRUSION", "x");
            FindingRepository repo = new FindingRepository(db);
            repo.saveAll(findings(session, 25));
            List<Long> seen = new ArrayList<>();
            long before = Long.MAX_VALUE;
            List<Finding> page;
            while (!(page = repo.findPage(before, 10)).isEmpty()) {
                page.forEach(f -> seen.add(f.id()));
                before = page.get(page.size() - 1).id();
            }
            assertEquals(25, seen.size());
            for (int i = 1; i < seen.size(); i++) {
                assertTrue(seen.get(i) < seen.get(i - 1), "strictly newest first, no duplicates");
            }
            repo.updateStatus(seen.get(0), "RESOLVED");
            assertEquals(1, repo.count("RESOLVED"));
            assertEquals(24, repo.count("OPEN"));
        }
    }

    @Test
    void dashboardAndRuleQueriesUseTheNewIndexes() throws SQLException {
        try (Database db = Database.inMemory()) {
            String status = plan(db, "SELECT COUNT(*) FROM finding WHERE status = ?", "OPEN");
            assertTrue(status.contains("idx_finding_status_sev"), status);
            // R18: the dashboard reads the small trigger-maintained table and never scans finding
            String dashboard = plan(db, FindingRepository.COUNT_BY_SEVERITY_SQL, null);
            assertTrue(dashboard.contains("finding_counts") && !dashboard.matches("(?s).*\bfinding\b(?!_).*"), dashboard);
            String rule = plan(db, "SELECT * FROM finding WHERE rule_id = ? ORDER BY created_at DESC LIMIT 10", "NET-001");
            assertTrue(rule.contains("idx_finding_rule"), rule);
        }
    }

    @Test
    void deletingAResolvedSessionCascadesButOpenFindingsBlockIt() throws SQLException {
        try (Database db = Database.inMemory()) {
            ScanSessionRepository sessions = new ScanSessionRepository(db);
            long session = sessions.begin("MALWARE", "x");
            FindingRepository findings = new FindingRepository(db);
            findings.saveAll(findings(session, 3));
            FileReportRepository reports = new FileReportRepository(db);
            reports.save(new FileReport(session, "a.exe", "PE", 1, "0".repeat(32), "f".repeat(64), 1.0, 5));
            // R18 (D7): a session with OPEN findings is protected by trg_session_delete_guard
            assertThrows(SQLException.class, () -> sessions.delete(session));
            assertEquals(3, findings.count(), "the refused delete changed nothing");
            for (Finding f : findings.findAll()) {
                findings.updateStatus(f.id(), "RESOLVED");
            }
            sessions.delete(session);
            assertEquals(0, findings.count());
            assertEquals(0, reports.count());
        }
    }

    @Test
    void triggerCountsStayExactAndStatusChangesAreAudited() throws SQLException {
        try (Database db = Database.inMemory()) {
            ScanSessionRepository sessions = new ScanSessionRepository(db);
            FindingRepository repo = new FindingRepository(db);
            long session = sessions.begin("INTRUSION", "x");
            List<Finding> saved = findings(session, 4);
            repo.saveAll(saved);
            repo.updateStatus(saved.get(0).id(), "FALSE_POSITIVE");
            repo.updateStatus(saved.get(1).id(), "RESOLVED");
            repo.delete(saved.get(2).id());
            assertEquals(exactCounts(db), triggerCounts(db), "finding_counts matches a full COUNT(*)");
            assertEquals("2", db.read(c -> TestData.scalar(c, "SELECT COUNT(*) FROM audit_log WHERE actor = 'trigger'")),
                    "one audit row per status change");
            repo.updateStatus(saved.get(3).id(), "RESOLVED");
            sessions.delete(session);       // cascade delete also runs the counting trigger
            assertEquals("0", db.read(c -> TestData.scalar(c, "SELECT COALESCE(SUM(n), 0) FROM finding_counts")));
        }
    }

    private static String exactCounts(Database db) throws SQLException {
        return db.read(c -> TestData.scalar(c, "SELECT group_concat(k, ',') FROM (SELECT severity || '/' || status || '=' || COUNT(*) AS k "
                + "FROM finding GROUP BY severity, status ORDER BY 1)"));
    }

    private static String triggerCounts(Database db) throws SQLException {
        return db.read(c -> TestData.scalar(c, "SELECT group_concat(k, ',') FROM (SELECT severity || '/' || status || '=' || n AS k "
                + "FROM finding_counts WHERE n > 0 ORDER BY 1)"));
    }

    @Test
    void countByModuleJoinsSessions() throws SQLException {
        try (Database db = Database.inMemory()) {
            ScanSessionRepository sessions = new ScanSessionRepository(db);
            FindingRepository repo = new FindingRepository(db);
            repo.saveAll(findings(sessions.begin("INTRUSION", "x"), 3));
            List<Finding> malware = findings(sessions.begin("MALWARE", "y"), 2);
            repo.saveAll(malware);
            repo.updateStatus(malware.get(0).id(), "FALSE_POSITIVE");
            assertEquals(Map.of("INTRUSION", 3, "MALWARE", 1), repo.countByModule());
        }
    }

    @Test
    void storedTimestampsAreUtcIso() throws SQLException {
        try (Database db = Database.inMemory()) {
            TestData.savedFinding(db);
            String stored = db.read(c -> {
                try (PreparedStatement ps = c.prepareStatement("SELECT created_at FROM finding"); ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return rs.getString(1);
                }
            });
            assertTrue(stored.endsWith("Z"), stored);
        }
    }

    @Test
    void sqlInjectionTextIsStoredAsPlainData() throws SQLException {
        try (Database db = Database.inMemory()) {
            long session = new ScanSessionRepository(db).begin("WEB", "x");
            String evil = "'; DROP TABLE finding;--";
            Finding f = new Finding("web", evil, "WEB-002", 70, evil, Map.of("q", evil), java.time.Instant.now());
            f.setSessionId(session);
            FindingRepository repo = new FindingRepository(db);
            repo.save(f);
            Finding back = repo.findById(f.id()).orElseThrow();
            assertEquals(evil, back.target());
            assertEquals(evil, back.description());
            assertEquals(evil, back.evidence().get("q"));
            assertEquals(1, repo.count(), "the table still exists");
        }
    }

    @Test
    void jsonFunctionsAreCompiledIntoTheDriver() throws SQLException {
        try (Database db = Database.inMemory()) {
            String value = db.read(c -> {
                try (PreparedStatement ps = c.prepareStatement("SELECT json_extract(?, '$.failures')")) {
                    ps.setString(1, "{\"failures\":\"7\"}");
                    try (ResultSet rs = ps.executeQuery()) {
                        rs.next();
                        return rs.getString(1);
                    }
                }
            });
            assertEquals("7", value);
        }
    }

    private static List<Finding> findings(long session, int n) {
        List<Finding> list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            Finding f = new Finding("ssh", "203.0.113." + i, "NET-001", 40 + (i % 50), "finding " + i);
            f.setSessionId(session);
            list.add(f);
        }
        return list;
    }

    private static String plan(Database db, String sql, String param) throws SQLException {
        return db.read(c -> explain(c, sql, param));
    }

    private static String explain(Connection c, String sql, String param) throws SQLException {
        StringBuilder sb = new StringBuilder();
        try (PreparedStatement ps = c.prepareStatement("EXPLAIN QUERY PLAN " + sql)) {
            if (param != null) {
                ps.setString(1, param);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    sb.append(rs.getString("detail")).append('\n');
                }
            }
        }
        return sb.toString();
    }

}
