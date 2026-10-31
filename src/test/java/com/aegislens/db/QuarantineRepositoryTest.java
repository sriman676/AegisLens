package com.aegislens.db;

import org.junit.jupiter.api.Test;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

class QuarantineRepositoryTest {

    @Test
    void addFindAndRestore() throws SQLException {
        try (Database db = Database.inMemory()) {
            QuarantineRepository repo = new QuarantineRepository(db);
            long id = repo.add("downloads/invoice.exe", "vault/1.bin", "e".repeat(64), "MAL-004 known bad hash");
            QuarantineEntry e = repo.find(id).orElseThrow();
            assertFalse(e.restored());
            assertEquals("vault/1.bin", e.vaultPath());
            assertTrue(repo.markRestored(id));
            assertTrue(repo.find(id).orElseThrow().restored());
            assertFalse(repo.markRestored(id + 100));
            assertEquals(1, repo.findAll().size());
        }
    }
}
