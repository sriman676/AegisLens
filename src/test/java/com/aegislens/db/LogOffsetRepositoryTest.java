package com.aegislens.db;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

class LogOffsetRepositoryTest {

    @TempDir
    Path dir;

    @Test
    void putThenGetAndOverwrite() throws SQLException {
        try (Database db = Database.inMemory()) {
            LogOffsetRepository repo = new LogOffsetRepository(db);
            Path log = dir.resolve("logs").resolve("auth.log");
            assertTrue(repo.get(log).isEmpty());
            repo.put(log, 1024, "abc");
            repo.put(dir.resolve("logs").resolve("..").resolve("logs").resolve("auth.log"), 2048, "abc");
            LogOffset o = repo.get(log).orElseThrow();
            assertEquals(2048, o.offset(), "the same file under a non-normalised path is the same row");
            assertEquals("abc", o.fingerprint());
            assertEquals(1, repo.count());
            assertThrows(IllegalArgumentException.class, () -> repo.put(log, -1, "x"));
        }
    }
}
