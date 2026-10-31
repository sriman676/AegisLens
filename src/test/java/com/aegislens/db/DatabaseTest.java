package com.aegislens.db;

import com.aegislens.core.Finding;
import com.aegislens.core.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class DatabaseTest {

    @TempDir
    Path dir;

    @Test
    void schemaCreatesTablesAndSeeds() throws SQLException {
        try (Database db = Database.inMemory()) {
            assertEquals(Database.SCHEMA_VERSION, db.schemaVersion());
            db.locked(c -> {
                try (Statement st = c.createStatement()) {
                    try (ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM rule")) {
                        rs.next();
                        assertEquals(27, rs.getInt(1));
                    }
                    try (ResultSet rs = st.executeQuery("SELECT value FROM ioc WHERE kind = 'HASH'")) {
                        assertTrue(rs.next(), "EICAR hash should be seeded");
                        assertEquals(64, rs.getString(1).length());
                    }
                    try (ResultSet rs = st.executeQuery("SELECT pattern FROM rule WHERE id = 'WEB-002'")) {
                        rs.next();
                        assertTrue(rs.getString(1).contains("union"), "regex with -- inside a string must survive schema parsing");
                    }
                }
                return null;
            });
        }
    }

    @Test
    void findingCrudAndStats() throws SQLException {
        try (Database db = Database.inMemory()) {
            long session = new ScanSessionRepository(db).begin("INTRUSION", "auth.log");
            FindingRepository repo = new FindingRepository(db);

            Finding f = new Finding("ssh", "203.0.113.45", "NET-001", 72, "7 failed logins",
                    Map.of("failures", "7", "window", "60s"), Instant.parse("2026-10-21T02:14:13Z"));
            f.setSessionId(session);
            repo.save(f);
            assertTrue(f.id() > 0);

            Finding g = new Finding("ssh", "203.0.113.45", "NET-003", 35, "odd hour login");
            g.setSessionId(session);
            repo.save(g);
            assertTrue(g.id() > f.id());

            Optional<Finding> loaded = repo.findById(f.id());
            assertTrue(loaded.isPresent());
            assertEquals("NET-001", loaded.get().ruleId());
            assertEquals("7", loaded.get().evidence().get("failures"));
            assertEquals(Instant.parse("2026-10-21T02:14:13Z"), loaded.get().timestamp());
            assertEquals("OPEN", loaded.get().status());

            assertEquals(2, repo.count());
            Map<Severity, Integer> counts = repo.countBySeverity();
            assertEquals(Integer.valueOf(1), counts.get(Severity.HIGH));
            assertEquals(Integer.valueOf(1), counts.get(Severity.MEDIUM));
            assertEquals(Integer.valueOf(0), counts.get(Severity.CRITICAL));
            assertEquals("203.0.113.45", repo.topTargets(5).get(0).target());
            assertEquals(2, repo.topTargets(5).get(0).count());

            repo.updateStatus(f.id(), "FALSE_POSITIVE");
            assertEquals("FALSE_POSITIVE", repo.findById(f.id()).orElseThrow().status());
            assertEquals(Integer.valueOf(0), repo.countBySeverity().get(Severity.HIGH), "false positives are not counted");

            assertEquals(2, repo.findAll().size());
            assertEquals(1, repo.findRecent(1).size());
            assertEquals(g.id(), repo.findRecent(1).get(0).id(), "newest first");

            repo.delete(f.id());
            assertEquals(1, repo.findAll().size());
        }
    }

    @Test
    void findingWithoutSessionIsRejected() throws SQLException {
        try (Database db = Database.inMemory()) {
            Finding f = new Finding("ssh", "x", "R", 10, "d");
            assertThrows(SQLException.class, () -> new FindingRepository(db).save(f));
        }
    }

    @Test
    void foreignKeysAreEnforced() throws SQLException {
        try (Database db = Database.inMemory()) {
            Finding f = new Finding("ssh", "x", "R", 10, "d");
            f.setSessionId(999);    // no such session
            assertThrows(SQLException.class, () -> new FindingRepository(db).save(f));
        }
    }

    @Test
    void transactionRollsBackOnFailure() throws SQLException {
        try (Database db = Database.inMemory()) {
            assertThrows(SQLException.class, () -> db.transaction(c -> {
                try (Statement st = c.createStatement()) {
                    st.executeUpdate("INSERT INTO setting (key, value) VALUES ('a', '1')");
                    st.executeUpdate("INSERT INTO setting (key, value) VALUES ('a', '2')");   // duplicate key
                }
                return null;
            }));
            db.locked(c -> {
                try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM setting")) {
                    rs.next();
                    assertEquals(0, rs.getInt(1), "the first insert must have been rolled back");
                }
                return null;
            });
        }
    }

    @Test
    void manyThreadsCanWriteAtOnceOnAFileDatabase() throws Exception {
        try (Database db = Database.open(dir.resolve("nested").resolve("t.db"))) {
            long session = new ScanSessionRepository(db).begin("MALWARE", "x");
            FindingRepository repo = new FindingRepository(db);
            List<Thread> threads = new ArrayList<>();
            List<Throwable> errors = java.util.Collections.synchronizedList(new ArrayList<>());
            for (int t = 0; t < 4; t++) {
                Thread th = new Thread(() -> {
                    try {
                        for (int i = 0; i < 50; i++) {
                            Finding f = new Finding("t", "target", "R", 10, "d");
                            f.setSessionId(session);
                            repo.save(f);
                            repo.findRecent(5);
                        }
                    } catch (Throwable e) {
                        errors.add(e);
                    }
                });
                threads.add(th);
                th.start();
            }
            for (Thread th : threads) {
                th.join(30_000);
            }
            assertTrue(errors.isEmpty(), "no thread may fail: " + errors);
            assertEquals(200, repo.count());
        }
    }
}
