package com.aegislens.db;

import org.junit.jupiter.api.Test;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

class AiExplanationRepositoryTest {

    @Test
    void onePerProviderAndNewerAnswerReplacesOlder() throws SQLException {
        try (Database db = Database.inMemory()) {
            long findingId = TestData.savedFinding(db);
            AiExplanationRepository repo = new AiExplanationRepository(db);
            repo.save(findingId, "offline", "template text");
            repo.save(findingId, "claude", "first answer");
            repo.save(findingId, "claude", "second answer");
            assertEquals("second answer", repo.find(findingId, "claude").orElseThrow().explanation());
            assertEquals(2, repo.findByFinding(findingId).size());
            assertTrue(repo.find(findingId, "gemini").isEmpty());
        }
    }

    @Test
    void explanationsGoAwayWithTheirFinding() throws SQLException {
        try (Database db = Database.inMemory()) {
            long findingId = TestData.savedFinding(db);
            AiExplanationRepository repo = new AiExplanationRepository(db);
            repo.save(findingId, "offline", "t");
            new FindingRepository(db).delete(findingId);
            assertEquals(0, repo.count(), "ON DELETE CASCADE");
        }
    }

    @Test
    void unknownFindingIsRejected() throws SQLException {
        try (Database db = Database.inMemory()) {
            assertThrows(SQLException.class, () -> new AiExplanationRepository(db).save(999, "offline", "t"));
        }
    }
}
