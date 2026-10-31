package com.aegislens.db;

import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class IocRepositoryTest {

    @Test
    void addAllCountsOnlyNewRowsAndSkipsDuplicates() throws SQLException {
        try (Database db = Database.inMemory()) {
            IocRepository repo = new IocRepository(db);
            assertEquals(2, repo.addAll("IP", List.of("203.0.113.1", "203.0.113.2", "203.0.113.1"), "feed-a"));
            assertEquals(1, repo.addAll("IP", List.of("203.0.113.2", "203.0.113.3"), "feed-a"));
            assertTrue(repo.exists("IP", "203.0.113.3"));
            assertFalse(repo.exists("DOMAIN", "203.0.113.3"), "kind is part of the key");
            assertEquals(Set.of("203.0.113.1", "203.0.113.2", "203.0.113.3"), repo.values("IP"));
        }
    }

    @Test
    void countByKindAndDeleteBySource() throws SQLException {
        try (Database db = Database.inMemory()) {
            IocRepository repo = new IocRepository(db);
            repo.addAll("DOMAIN", List.of("bad.example", "worse.example"), "feed-b");
            repo.addAll("IP", List.of("198.51.100.7"), "manual");
            Map<String, Integer> counts = repo.countByKind();
            assertEquals(2, counts.get("DOMAIN"));
            assertEquals(1, counts.get("IP"));
            assertEquals(1, counts.get("HASH"), "the EICAR seed hash");
            assertEquals(2, repo.deleteBySource("feed-b"));
            assertFalse(repo.exists("DOMAIN", "bad.example"));
            assertTrue(repo.exists("IP", "198.51.100.7"));
        }
    }

    @Test
    void unknownKindIsRejected() throws SQLException {
        try (Database db = Database.inMemory()) {
            assertThrows(IllegalArgumentException.class, () -> new IocRepository(db).addAll("EMAIL", List.of("x"), "m"));
        }
    }
}
