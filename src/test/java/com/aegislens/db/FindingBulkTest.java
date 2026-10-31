package com.aegislens.db;

import com.aegislens.core.Finding;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** R18 D8: bulk status changes and deletes run in one transaction and roll back completely on failure. */
class FindingBulkTest {

    private Database db;
    private FindingRepository repo;
    private final List<Long> ids = new ArrayList<>();

    @BeforeEach
    void setUp() throws SQLException {
        db = Database.inMemory();
        repo = new FindingRepository(db);
        long session = new ScanSessionRepository(db).begin("INTRUSION", "auth.log");
        for (int i = 0; i < 6; i++) {
            Finding f = new Finding("ssh", i < 4 ? "203.0.113.45" : "198.51.100.7", "NET-001", 72, "failed logins " + i);
            f.setSessionId(session);
            repo.save(f);
            ids.add(f.id());
        }
    }

    @AfterEach
    void tearDown() throws SQLException {
        db.close();
    }

    @Test
    void bulkStatusAndDeleteChangeExactlyTheChosenRows() throws SQLException {
        assertEquals(3, repo.updateStatusMany(ids.subList(0, 3), "RESOLVED"));
        assertEquals(3, repo.count("RESOLVED"));
        assertEquals(2, repo.deleteMany(List.of(ids.get(4), ids.get(5))));
        assertEquals(4, repo.count());
        assertEquals(0, repo.deleteMany(List.of()), "an empty selection does nothing");
        assertEquals(0, repo.deleteMany(List.of(999_999L)), "an unknown id deletes nothing");
    }

    @Test
    void aFailingRowRollsBackTheWholeBatch() throws SQLException {
        assertThrows(SQLException.class, () -> repo.updateStatusMany(ids, "NOT_A_STATUS"), "CHECK constraint");
        assertEquals(6, repo.count("OPEN"), "no row changed");
        assertEquals("6", db.read(c -> {
            try (var st = c.createStatement(); var rs = st.executeQuery(
                    "SELECT SUM(n) FROM finding_counts WHERE status = 'OPEN'")) {
                return rs.next() ? rs.getString(1) : null;
            }
        }), "the counting triggers were rolled back too");
    }

    @Test
    void markTargetFalsePositiveOnlyTouchesOpenFindingsOfThatTarget() throws SQLException {
        repo.updateStatus(ids.get(0), "RESOLVED");
        assertEquals(3, repo.markTargetFalsePositive("203.0.113.45"));
        assertEquals(3, repo.count("FALSE_POSITIVE"));
        assertEquals(1, repo.count("RESOLVED"), "a resolved finding keeps its status");
        assertEquals(2, repo.count("OPEN"), "the other target is untouched");
    }
}
