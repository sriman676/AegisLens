package com.aegislens.db;

import com.aegislens.core.Finding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.PreparedStatement;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** RetentionJob and BackupService. */
class MaintenanceTest {

    private static final Instant NOW = Instant.parse("2026-10-29T12:00:00Z");

    @TempDir
    Path dir;

    @Test
    void retentionDeletesOnlyOldClosedFindingsAndKeepsOpenOnes() throws Exception {
        // R18 changed the rule: before, every finding older than 90 days was deleted; now OPEN ones are kept
        try (Database db = Database.open(dir.resolve("r.db"))) {
            long session = new ScanSessionRepository(db).begin("INTRUSION", "x");
            FindingRepository findings = new FindingRepository(db);
            Finding oldOpen = finding(session, NOW.minus(Duration.ofDays(91)));
            findings.saveAll(List.of(closed(session, NOW.minus(Duration.ofDays(91)), "RESOLVED"),
                    closed(session, NOW.minus(Duration.ofDays(91)), "FALSE_POSITIVE"),
                    oldOpen, closed(session, NOW.minus(Duration.ofDays(5)), "RESOLVED")));
            oldAuditRow(db, NOW.minus(Duration.ofDays(400)));
            new AuditLogRepository(db).append("analyst", "RECENT", null);

            RetentionJob.Result result = new RetentionJob(db).runOnce(NOW);
            assertEquals(2, result.findingsDeleted(), "the old RESOLVED and FALSE_POSITIVE ones");
            assertEquals(1, result.auditDeleted());
            assertEquals(2, findings.count());
            assertTrue(findings.findById(oldOpen.id()).isPresent(), "an old OPEN finding is never aged out");
            assertTrue(result.sizeBytes() > 0);
        }
    }

    @Test
    void retentionDeletesOnlyOldFinishedEmptySessions() throws Exception {
        try (Database db = Database.inMemory()) {
            ScanSessionRepository sessions = new ScanSessionRepository(db);
            long emptyOld = sessions.begin("MALWARE", "empty folder");
            long running = sessions.begin("INTRUSION", "live tail");
            long withFinding = sessions.begin("INTRUSION", "auth.log");
            long emptyRecent = sessions.begin("WEB", "urls.txt");
            new FindingRepository(db).saveAll(List.of(closed(withFinding, NOW.minus(Duration.ofDays(1)), "RESOLVED")));
            for (long id : new long[] {emptyOld, withFinding, emptyRecent}) {
                sessions.finish(id, true);
            }
            backdateFinish(db, emptyOld, "2026-01-01 00:00:00");
            backdateFinish(db, withFinding, "2026-01-01 00:00:00");
            backdateFinish(db, emptyRecent, "2026-10-28 00:00:00");

            assertEquals(1, new RetentionJob(db).runOnce(NOW).sessionsDeleted());
            assertEquals(3, sessions.count());
            assertEquals("0", db.read(c -> TestData.scalar(c, "SELECT COUNT(*) FROM scan_session WHERE id = " + emptyOld)));
            assertEquals("1", db.read(c -> TestData.scalar(c, "SELECT COUNT(*) FROM scan_session WHERE id = " + running)), "RUNNING is kept");
        }
    }

    @Test
    void retentionDaysComeFromSettings() throws Exception {
        try (Database db = Database.inMemory()) {
            long session = new ScanSessionRepository(db).begin("INTRUSION", "x");
            new FindingRepository(db).saveAll(List.of(closed(session, NOW.minus(Duration.ofDays(10)), "RESOLVED")));
            new SettingRepository(db).put(RetentionJob.FINDING_DAYS_SETTING, "7");
            assertEquals(1, new RetentionJob(db).runOnce(NOW).findingsDeleted());
        }
    }

    @Test
    void vacuumRunsOnlyWhenMuchSpaceIsFree() throws Exception {
        try (Database db = Database.open(dir.resolve("v.db"))) {
            RetentionJob job = new RetentionJob(db);
            assertFalse(job.runOnce(NOW).vacuumed(), "fresh database: nothing to reclaim");
            long session = new ScanSessionRepository(db).begin("INTRUSION", "x");
            List<Finding> many = new ArrayList<>();
            for (int i = 0; i < 3000; i++) {
                many.add(closed(session, NOW.minus(Duration.ofDays(200)), "FALSE_POSITIVE"));
            }
            new FindingRepository(db).saveAll(many);
            RetentionJob.Result result = job.runOnce(NOW);
            assertEquals(3000, result.findingsDeleted());
            assertTrue(result.vacuumed(), "deleting most rows leaves more than 20 percent free");
            assertTrue(job.freeRatio() < RetentionJob.VACUUM_FREE_RATIO);
        }
    }

    @Test
    void backupWritesAReadableCopyAndKeepsTheNewestSeven() throws Exception {
        Path backups = dir.resolve("backups");
        try (Database db = Database.open(dir.resolve("b.db"))) {
            TestData.savedFinding(db);
            BackupService service = new BackupService(db);
            LocalDate day = LocalDate.of(2026, 10, 1);
            for (int i = 0; i < 9; i++) {
                service.backup(backups, day.plusDays(i));
            }
            List<Path> kept = BackupService.list(backups);
            assertEquals(BackupService.KEEP, kept.size());
            assertEquals("backup-2026-10-09.db", kept.get(0).getFileName().toString(), "newest first");
            try (var files = Files.list(backups)) {
                assertTrue(files.noneMatch(p -> p.toString().endsWith(".tmp")), "no temporary file is left behind");
            }
            try (Database copy = Database.open(kept.get(0))) {
                assertEquals(1, new FindingRepository(copy).count());
            }
        }
    }

    private static Finding finding(long session, Instant at) {
        Finding f = new Finding("ssh", "203.0.113.9", "NET-001", 70, "old", java.util.Map.of(), at);
        f.setSessionId(session);
        return f;
    }

    private static Finding closed(long session, Instant at, String status) {
        Finding f = finding(session, at);
        f.setStatus(status);
        return f;
    }

    private static void backdateFinish(Database db, long session, String finishedAt) throws Exception {
        db.locked(c -> {
            try (PreparedStatement ps = c.prepareStatement("UPDATE scan_session SET finished_at = ? WHERE id = ?")) {
                ps.setString(1, finishedAt);
                ps.setLong(2, session);
                return ps.executeUpdate();
            }
        });
    }


    private static void oldAuditRow(Database db, Instant at) throws Exception {
        db.locked(c -> {
            try (PreparedStatement ps = c.prepareStatement("INSERT INTO audit_log (actor, action, at) VALUES ('a', 'OLD', ?)")) {
                ps.setString(1, at.toString());
                return ps.executeUpdate();
            }
        });
    }
}
