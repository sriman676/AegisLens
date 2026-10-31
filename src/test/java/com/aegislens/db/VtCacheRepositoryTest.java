package com.aegislens.db;

import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class VtCacheRepositoryTest {

    @Test
    void saveFindAndReplace() throws SQLException {
        try (Database db = Database.inMemory()) {
            VtCacheRepository repo = new VtCacheRepository(db);
            String sha = "a".repeat(64);
            assertTrue(repo.find(sha).isEmpty());
            repo.save(new VtResult(sha, false, 0, 0, 0, Instant.parse("2026-10-01T00:00:00Z")));
            repo.save(new VtResult(sha, true, 41, 2, 70, Instant.parse("2026-10-29T00:00:00Z")));
            VtResult r = repo.find(sha).orElseThrow();
            assertTrue(r.known());
            assertEquals(41, r.malicious());
            assertEquals(Instant.parse("2026-10-29T00:00:00Z"), r.checkedAt());
            assertEquals(1, repo.count());
        }
    }
}
