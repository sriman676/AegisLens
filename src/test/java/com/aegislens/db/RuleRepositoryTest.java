package com.aegislens.db;

import com.aegislens.core.Severity;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

class RuleRepositoryTest {

    @Test
    void seededRulesCanBeReadToggledAndTuned() throws SQLException {
        try (Database db = Database.inMemory()) {
            RuleRepository repo = new RuleRepository(db);
            assertEquals(27, repo.findAll().size());
            RuleDef brute = repo.findById("NET-001").orElseThrow();
            assertEquals(5.0, brute.threshold());
            assertEquals(Severity.HIGH, brute.severity());
            assertNull(repo.findById("NET-003").orElseThrow().threshold(), "NULL threshold stays null");

            int intrusion = repo.findEnabled("INTRUSION").size();
            assertTrue(repo.setEnabled("NET-001", false));
            assertEquals(intrusion - 1, repo.findEnabled("INTRUSION").size());
            assertTrue(repo.setThreshold("NET-001", 8));
            assertEquals(8.0, repo.findById("NET-001").orElseThrow().threshold());
            assertFalse(repo.setThreshold("NOPE-1", 1), "unknown id");
        }
    }

    @Test
    void saveUpsertsAndDeleteRemoves() throws SQLException {
        try (Database db = Database.inMemory()) {
            RuleRepository repo = new RuleRepository(db);
            repo.save(new RuleDef("TST-001", "WEB", "test", null, 1.5, Severity.LOW, true));
            repo.save(new RuleDef("TST-001", "WEB", "renamed", "x+", null, Severity.MEDIUM, false));
            RuleDef r = repo.findById("TST-001").orElseThrow();
            assertEquals("renamed", r.name());
            assertNull(r.threshold());
            assertFalse(r.enabled());
            repo.delete("TST-001");
            assertTrue(repo.findById("TST-001").isEmpty());
        }
    }
}
