package com.aegislens.db;

import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class FeedStateRepositoryTest {

    @Test
    void saveGetAndUpdate() throws SQLException {
        try (Database db = Database.inMemory()) {
            FeedStateRepository repo = new FeedStateRepository(db);
            Instant t = Instant.parse("2026-10-29T10:00:00Z");
            repo.save(new FeedState("feodo", "https://feeds.example/ips.txt", t, null, null, null, 0, "timeout"));
            repo.save(new FeedState("feodo", "https://feeds.example/ips.txt", t, t, "\"etag1\"",
                    "Wed, 29 Oct 2026 10:00:00 GMT", 412, null));
            repo.save(new FeedState("abuse", "https://other.example/list", t, t, null, null, 3, null));
            FeedState s = repo.get("feodo").orElseThrow();
            assertEquals(412, s.entries());
            assertEquals(t, s.lastSuccess());
            assertNull(s.lastError());
            assertEquals("\"etag1\"", s.etag());
            assertEquals("abuse", repo.all().get(0).name(), "sorted by name");
        }
    }
}
