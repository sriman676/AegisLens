package com.aegislens.db;

import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FileReportRepositoryTest {

    @Test
    void saveFindBySha256AndRecent() throws SQLException {
        try (Database db = Database.inMemory()) {
            long session = new ScanSessionRepository(db).begin("MALWARE", "samples");
            FileReportRepository repo = new FileReportRepository(db);
            String sha = "b".repeat(64);
            long first = repo.save(report(session, "a.exe", sha, 40), session);
            repo.save(report(session, "b.exe", "c".repeat(64), 10));
            long third = repo.save(report(session, "a-copy.exe", sha, 45), session);
            List<FileReport> same = repo.findBySha256(sha);
            assertEquals(List.of(third, first), same.stream().map(FileReport::id).toList(), "newest first");
            assertEquals(7.1, repo.findById(first).orElseThrow().entropy(), 1e-9);
            assertEquals(2, repo.findRecent(2).size());
            assertEquals(3, repo.findAll().size());
            repo.delete(first);
            assertTrue(repo.findById(first).isEmpty());
        }
    }

    @Test
    void invalidRiskScoreAndUnknownSessionAreRejected() throws SQLException {
        try (Database db = Database.inMemory()) {
            FileReportRepository repo = new FileReportRepository(db);
            assertThrows(IllegalArgumentException.class, () -> repo.save(report(1, "x", "d".repeat(64), 101)));
            assertThrows(SQLException.class, () -> repo.save(report(999, "x", "d".repeat(64), 1)));
        }
    }

    private static FileReport report(long session, String path, String sha, int risk) {
        return new FileReport(session, path, "PE", 4096, "0".repeat(32), sha, 7.1, risk);
    }
}
