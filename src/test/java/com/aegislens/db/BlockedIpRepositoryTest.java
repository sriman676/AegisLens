package com.aegislens.db;

import org.junit.jupiter.api.Test;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

class BlockedIpRepositoryTest {

    @Test
    void blockUnblockAndList() throws SQLException {
        try (Database db = Database.inMemory()) {
            BlockedIpRepository repo = new BlockedIpRepository(db);
            repo.block("203.0.113.45", "brute force");
            repo.block("203.0.113.45", "brute force, again");
            repo.block("198.51.100.9", "scan");
            assertTrue(repo.isBlocked("203.0.113.45"));
            assertEquals("brute force, again", repo.findById("203.0.113.45").orElseThrow().reason());
            assertEquals(2, repo.findAll().size());
            assertTrue(repo.findAll().get(0).blockedAt().toString().endsWith("Z"));
            assertTrue(repo.unblock("203.0.113.45"));
            assertFalse(repo.unblock("203.0.113.45"));
            assertFalse(repo.isBlocked("203.0.113.45"));
        }
    }
}
