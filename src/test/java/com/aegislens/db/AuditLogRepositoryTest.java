package com.aegislens.db;

import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AuditLogRepositoryTest {

    @Test
    void appendAndReadNewestFirst() throws SQLException {
        try (Database db = Database.inMemory()) {
            AuditLogRepository repo = new AuditLogRepository(db);
            long first = repo.append("analyst", "BLOCK_IP", "203.0.113.45");
            long second = repo.append("analyst", "MARK_FALSE_POSITIVE", "finding 7");
            assertTrue(second > first);
            List<AuditEntry> recent = repo.recent(1);
            assertEquals(1, recent.size());
            assertEquals("MARK_FALSE_POSITIVE", recent.get(0).action());
            assertTrue(recent.get(0).at().toString().endsWith("Z"));
            assertEquals(2, repo.recent(10).size());
        }
    }
}
