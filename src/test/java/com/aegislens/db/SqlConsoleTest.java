package com.aegislens.db;

import com.aegislens.core.Finding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** R18 D13: the console runs reads, refuses everything else, and caps its results. */
class SqlConsoleTest {

    @TempDir
    Path dir;

    @Test
    void selectReturnsColumnsAndRows() throws SQLException {
        try (Database db = Database.inMemory()) {
            TestData.savedFinding(db);
            SqlConsole.Result r = new SqlConsole(db).run("SELECT rule_id, target, module FROM v_finding_detail;");
            assertEquals(List.of("rule_id", "target", "module"), r.columns());
            assertEquals(List.of(List.of("NET-001", "203.0.113.45", "INTRUSION")), r.rows());
            assertFalse(r.truncated());
        }
    }

    @Test
    void withAndExplainAndKeywordsInsideStringsAreAllowed() throws SQLException {
        try (Database db = Database.inMemory()) {
            SqlConsole console = new SqlConsole(db);
            assertEquals(1, console.run("WITH t AS (SELECT 1 AS x) SELECT x FROM t").rows().size());
            assertFalse(console.run("EXPLAIN QUERY PLAN SELECT * FROM finding WHERE rule_id = 'NET-001'").rows().isEmpty());
            assertEquals("DROP TABLE finding", console.run("SELECT 'DROP TABLE finding'").rows().get(0).get(0));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "DELETE FROM finding",
            "UPDATE finding SET status = 'RESOLVED'",
            "SELECT 1; DELETE FROM finding",
            "ATTACH DATABASE 'x.db' AS x",
            "PRAGMA writable_schema = 1",
            "WITH t AS (SELECT 1) DELETE FROM finding",
            "SELECT load_extension('evil')",
            "SELECT 1 -- hidden",
            "",
            "   ",
    })
    void writesAndTricksAreRefusedBeforeReachingTheDatabase(String sql) throws SQLException {
        try (Database db = Database.inMemory()) {
            assertThrows(SqlConsole.RefusedException.class, () -> new SqlConsole(db).run(sql));
        }
    }

    @Test
    void theDatabaseItselfRefusesWritesEvenIfTheTextCheckMissedOne() throws SQLException {
        try (Database db = Database.inMemory()) {
            long id = TestData.savedFinding(db);
            // a write that passes the word check: SQLite's query_only must stop it
            SQLException e = assertThrows(SQLException.class,
                    () -> db.read(c -> {
                        try (var st = c.createStatement()) {
                            st.execute("PRAGMA query_only = 1");
                            try {
                                return st.executeUpdate("UPDATE finding SET status = 'RESOLVED'");
                            } finally {
                                st.execute("PRAGMA query_only = 0");
                            }
                        }
                    }));
            assertTrue(e.getMessage().toLowerCase().contains("readonly"), e.getMessage());
            assertEquals(1, new FindingRepository(db).count("OPEN"));
            new FindingRepository(db).updateStatus(id, "RESOLVED");      // the writer still works afterwards
            assertEquals(1, new FindingRepository(db).count("RESOLVED"));
        }
    }

    @Test
    void writerIsNotLeftReadOnlyAfterAConsoleQuery() throws SQLException {
        try (Database db = Database.inMemory()) {
            new SqlConsole(db).run("SELECT 1");
            assertDoesNotThrow(() -> TestData.savedFinding(db));
        }
    }

    @Test
    void resultsAreCappedAndFileDatabasesUseTheReadOnlyReader() throws SQLException {
        try (Database db = Database.open(dir.resolve("c.db"))) {
            long session = new ScanSessionRepository(db).begin("INTRUSION", "x");
            List<Finding> many = new ArrayList<>();
            for (int i = 0; i < SqlConsole.MAX_ROWS + 20; i++) {
                Finding f = new Finding("ssh", "203.0.113.1", "NET-001", 70, "row " + i);
                f.setSessionId(session);
                many.add(f);
            }
            new FindingRepository(db).saveAll(many);
            SqlConsole.Result r = new SqlConsole(db).run("SELECT id FROM finding");
            assertEquals(SqlConsole.MAX_ROWS, r.rows().size());
            assertTrue(r.truncated());
            assertDoesNotThrow(() -> TestData.savedFinding(db), "the writer connection is untouched");
        }
    }
}
