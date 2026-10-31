package com.aegislens.db;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Writer/reader connections, nest-safe transactions, migrations and schema rules. */
class DatabaseCoreTest {

    @TempDir
    Path dir;

    @Test
    void fileDatabaseReadsThroughAReadOnlyConnection() throws SQLException {
        try (Database db = Database.open(dir.resolve("a.db"))) {
            assertTrue(db.hasSeparateReader());
            putSetting(db, "k", "v");
            assertEquals(1, countSettings(db), "reader sees committed writes");
            assertThrows(SQLException.class, () -> db.read(c -> {
                try (Statement st = c.createStatement()) {
                    return st.executeUpdate("INSERT INTO setting (key, value) VALUES ('x', 'y')");
                }
            }), "the reader is query_only");
        }
    }

    @Test
    void inMemoryDatabaseUsesOneConnection() throws SQLException {
        try (Database db = Database.inMemory()) {
            assertFalse(db.hasSeparateReader());
            putSetting(db, "k", "v");
            assertEquals(1, countSettings(db));
        }
    }

    @Test
    void writingWhileHoldingTheReadLockIsRejected() throws SQLException {
        try (Database db = Database.open(dir.resolve("b.db"))) {
            assertThrows(IllegalStateException.class, () -> db.read(c -> {
                putSetting(db, "k", "v");
                return null;
            }));
        }
    }

    @Test
    void nestedTransactionDoesNotCommitEarly() throws SQLException {
        try (Database db = Database.open(dir.resolve("c.db"))) {
            db.transaction(c -> {
                insertSetting(c, "outer");
                db.transaction(inner -> insertSetting(inner, "inner"));
                assertEquals(0, countSettings(db), "nothing is visible to readers before the outer commit");
                return null;
            });
            assertEquals(2, countSettings(db));
        }
    }

    @Test
    void failureInsideNestedTransactionRollsBackEverything() throws SQLException {
        try (Database db = Database.open(dir.resolve("d.db"))) {
            assertThrows(SQLException.class, () -> db.transaction(c -> {
                insertSetting(c, "outer");
                return db.transaction(inner -> {
                    insertSetting(inner, "inner");
                    return insertSetting(inner, "inner");      // duplicate key
                });
            }));
            assertEquals(0, countSettings(db));
            putSetting(db, "after", "1");                      // autocommit is back on
            assertEquals(1, countSettings(db));
        }
    }

    @Test
    void versionOneFileIsMigratedBeforeTheCreateScript() throws Exception {
        Path file = dir.resolve("v1.db");
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + file); Statement st = c.createStatement()) {
            for (String sql : fixture("/db/schema-v1.sql").split(";")) {
                if (!sql.isBlank()) {
                    st.execute(sql);
                }
            }
        }
        try (Database db = Database.open(file)) {
            assertEquals(Database.SCHEMA_VERSION, db.schemaVersion());
            assertEquals("OPEN", db.read(c -> TestData.scalar(c, "SELECT status FROM finding WHERE description = 'old finding'")));
            assertEquals("idx_finding_status_sev",
                    db.read(c -> TestData.scalar(c, "SELECT name FROM sqlite_master WHERE name = 'idx_finding_status_sev'")));
            assertEquals("27", db.read(c -> TestData.scalar(c, "SELECT COUNT(*) FROM rule")), "new tables and seeds were added");
            assertEquals("1", db.read(c -> TestData.scalar(c, "SELECT SUM(n) FROM finding_counts")),
                    "v3 backfills the counts table from the findings already in the file (counted once, not twice)");
        }
    }

    @Test
    void fileFromANewerAppIsRefused() throws Exception {
        Path file = dir.resolve("future.db");
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + file); Statement st = c.createStatement()) {
            st.execute("PRAGMA user_version = " + (Database.SCHEMA_VERSION + 1));
        }
        assertThrows(SQLException.class, () -> Database.open(file));
    }

    @Test
    void version3FileGetsTheCoveringIndexesInsteadOfTheNarrowOnes() throws Exception {
        Path file = dir.resolve("v3.db");
        Database.open(file).close();
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + file); Statement st = c.createStatement()) {
            st.execute("CREATE INDEX idx_finding_target ON finding(target)");      // what a v3 file has
            st.execute("CREATE INDEX idx_finding_rule ON finding(rule_id, created_at)");
            st.execute("PRAGMA user_version = 3");
        }
        try (Database db = Database.open(file)) {
            assertEquals(Database.SCHEMA_VERSION, db.schemaVersion());
            String names = db.read(c -> TestData.scalar(c,
                    "SELECT group_concat(name, ' ') FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_finding_%'"));
            assertFalse((" " + names + " ").contains(" idx_finding_target "), names);
            assertFalse((" " + names + " ").contains(" idx_finding_rule "), names);
            assertTrue(names.contains("idx_finding_target_stats") && names.contains("idx_finding_rule_stats"), names);
        }
    }

    @Test
    void version4FileKeepsItsFindingsAndAcceptsHostSessions() throws Exception {
        Path file = dir.resolve("v4.db");
        Database.open(file).close();
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + file); Statement st = c.createStatement()) {
            st.execute("INSERT INTO scan_session (module, target) VALUES ('INTRUSION', 'auth.log')");
            st.execute("INSERT INTO finding (session_id, source, target, rule_id, severity, score, description, evidence) "
                    + "VALUES (1, 'ssh', '203.0.113.45', 'NET-001', 'HIGH', 70, 'old finding', '{}')");
            st.execute("PRAGMA foreign_keys = OFF");                      // rebuild scan_session the way v4 had it
            st.execute("DROP VIEW v_finding_detail");
            st.execute("CREATE TABLE s4 (id INTEGER PRIMARY KEY AUTOINCREMENT, module TEXT NOT NULL CHECK (module IN "
                    + "('MALWARE','INTRUSION','WEB','SANDBOX')), started_at TEXT NOT NULL DEFAULT (datetime('now')), "
                    + "finished_at TEXT, target TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'RUNNING')");
            st.execute("INSERT INTO s4 SELECT * FROM scan_session");
            st.execute("DROP TABLE scan_session");
            st.execute("ALTER TABLE s4 RENAME TO scan_session");
            st.execute("PRAGMA user_version = 4");
        }
        try (Database db = Database.open(file)) {
            assertEquals(Database.SCHEMA_VERSION, db.schemaVersion());
            assertEquals("old finding", db.read(c -> TestData.scalar(c,
                    "SELECT description FROM v_finding_detail WHERE module = 'INTRUSION'")), "finding, session and view survive");
            db.locked(c -> {
                try (Statement st = c.createStatement()) {
                    st.execute("INSERT INTO scan_session (module, target) VALUES ('HOST', 'sysmon.xml')");
                }
                return null;
            });
            assertEquals("1", db.read(c -> TestData.scalar(c,
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = 'trg_session_delete_guard'")), "the guard trigger is back");
            assertThrows(SQLException.class, () -> db.locked(c -> {
                try (Statement st = c.createStatement()) {
                    st.execute("DELETE FROM scan_session WHERE id = 1");          // still has an OPEN finding
                }
                return null;
            }));
        }
    }

    @Test
    void goSeparatorLoaderKeepsTriggerBodiesWhole() throws SQLException {
        List<String> statements = Database.readStatements("/schema.sql");
        String trigger = statements.stream().filter(s -> s.contains("trg_counts_insert")).findFirst().orElseThrow();
        assertTrue(trigger.contains("BEGIN") && trigger.strip().endsWith("END;"), "the whole trigger body is one statement");
        assertTrue(statements.stream().noneMatch(s -> s.contains("-- GO")), "separator lines are removed");
        try (Database db = Database.inMemory()) {
            assertEquals("5", db.read(c -> TestData.scalar(c,
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name NOT LIKE 'trg_fts%'")),
                    "counts (3), status audit and session guard triggers are installed");
            assertEquals("2", db.read(c -> TestData.scalar(c, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'view'")));
        }
    }

    private static void putSetting(Database db, String key, String value) throws SQLException {
        db.locked(c -> insert(c, key, value));
    }

    private static int insertSetting(Connection c, String key) throws SQLException {
        return insert(c, key, "1");
    }

    private static int insert(Connection c, String key, String value) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("INSERT INTO setting (key, value) VALUES (?, ?)")) {
            ps.setString(1, key);
            ps.setString(2, value);
            return ps.executeUpdate();
        }
    }

    private static int countSettings(Database db) throws SQLException {
        return Integer.parseInt(db.read(c -> TestData.scalar(c, "SELECT COUNT(*) FROM setting")));
    }

    private static String fixture(String name) throws IOException {
        try (InputStream in = DatabaseCoreTest.class.getResourceAsStream(name)) {
            assertNotNull(in, name);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
