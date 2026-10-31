package com.aegislens.db;

import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SettingRepositoryTest {

    @Test
    void putGetAndOverwrite() throws SQLException {
        try (Database db = Database.inMemory()) {
            SettingRepository repo = new SettingRepository(db);
            assertEquals("90", repo.getOrDefault("retention.days", "90"));
            repo.put("retention.days", "30");
            repo.put("retention.days", "60");
            assertEquals("60", repo.get("retention.days").orElseThrow());
            repo.put("ai.provider", "offline");
            assertEquals(List.of("ai.provider", "retention.days"), List.copyOf(repo.all().keySet()), "sorted by key");
        }
    }

    @Test
    void secretsAreNeverStored() throws SQLException {
        try (Database db = Database.inMemory()) {
            SettingRepository repo = new SettingRepository(db);
            for (String key : List.of("CLAUDE_API_KEY", "gemini.apiKey", "vt.token", "smtp.password", "client_secret")) {
                assertThrows(IllegalArgumentException.class, () -> repo.put(key, "x"), key);
            }
            assertEquals(0, repo.count());
        }
    }
}
