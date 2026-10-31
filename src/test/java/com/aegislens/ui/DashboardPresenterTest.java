package com.aegislens.ui;

import com.aegislens.core.Finding;
import com.aegislens.core.Severity;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.ScanSessionRepository;
import com.aegislens.intrusion.MonitorManager.SourceStatus;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DashboardPresenterTest {

    @Test
    void snapshotCollectsEveryDashboardNumber() throws Exception {
        try (Database db = Database.inMemory()) {
            ScanSessionRepository sessions = new ScanSessionRepository(db);
            FindingRepository repo = new FindingRepository(db);
            long intrusion = sessions.begin("INTRUSION", "auth.log");
            long malware = sessions.begin("MALWARE", "files");
            save(repo, intrusion, "203.0.113.45", 90);
            save(repo, intrusion, "203.0.113.45", 60);
            save(repo, intrusion, "198.51.100.7", 35);
            save(repo, malware, "invoice.exe", 50);

            SourceStatus tail = new SourceStatus("/var/log/auth.log", "TIMED_WAITING", 10, 9, 1, 0, 2, Instant.now());
            SourceStatus dead = new SourceStatus("/var/log/old.log", "TERMINATED", 0, 0, 0, 0, 0, Instant.now());
            DashboardPresenter p = new DashboardPresenter(db, () -> List.of("offline", "claude"), () -> List.of(tail, dead));
            DashboardPresenter.Snapshot s = p.snapshot();

            assertEquals(4, s.total());
            assertEquals(1, s.bySeverity().get(Severity.CRITICAL));
            assertEquals(3, s.byModule().get("INTRUSION"));
            assertEquals(1, s.byModule().get("MALWARE"));
            assertEquals("203.0.113.45", s.topTargets().get(0).target());
            assertEquals(4, s.recent().size());
            assertEquals(1, s.runningSources());
            assertTrue(s.dbBytes() > 0);

            List<String> status = DashboardPresenter.statusItems(s);
            assertTrue(status.get(1).contains("claude"));
            assertEquals("Live monitors: 1 of 2 running", status.get(2));
            assertEquals("4 active findings", status.get(3));
        }
    }

    @Test
    void hourlyBucketsForTheTimelineAndSparklines() throws Exception {
        try (Database db = Database.inMemory()) {
            long session = new ScanSessionRepository(db).begin("INTRUSION", "x");
            FindingRepository repo = new FindingRepository(db);
            Instant now = Instant.parse("2026-10-29T14:35:00Z");
            saveAt(repo, session, 90, now.minusSeconds(60));                 // this hour
            saveAt(repo, session, 90, now.minusSeconds(3 * 3600));           // 3 hours ago
            saveAt(repo, session, 40, now.minusSeconds(3 * 3600 + 60));
            saveAt(repo, session, 90, now.minusSeconds(30 * 3600));          // outside the 24 h window
            DashboardPresenter p = new DashboardPresenter(db, List::of, List::of);
            java.util.Map<Severity, int[]> hourly = p.hourly(now);
            int[] critical = hourly.get(Severity.CRITICAL);
            assertEquals(DashboardPresenter.HOURS, critical.length);
            assertEquals(1, critical[23], "current hour is the last bucket");
            assertEquals(1, critical[20]);
            assertEquals(2, java.util.Arrays.stream(critical).sum());
            assertEquals(1, hourly.get(Severity.MEDIUM)[20]);
            List<String> labels = DashboardPresenter.hourLabels(now, java.time.ZoneOffset.UTC);
            assertEquals("15:00", labels.get(0));
            assertEquals("14:00", labels.get(23));
        }
    }

    private static void saveAt(FindingRepository repo, long session, int score, Instant at) throws Exception {
        Finding f = new Finding("t", "203.0.113.1", "NET-001", score, "x", java.util.Map.of(), at);
        f.setSessionId(session);
        repo.save(f);
    }

    @Test
    void formatting() {
        assertEquals("512 B", DashboardPresenter.humanBytes(512));
        assertEquals("1.5 KB", DashboardPresenter.humanBytes(1536));
        assertEquals("2.0 MB", DashboardPresenter.humanBytes(2L * 1024 * 1024));
        assertEquals("203.0.113.45   ·  1 finding",
                DashboardPresenter.attackerLine(new FindingRepository.TargetCount("203.0.113.45", 1)));
        DashboardPresenter.Snapshot empty = new DashboardPresenter.Snapshot(java.util.Map.of(), java.util.Map.of(), List.of(),
                List.of(), 0, List.of("offline"), List.of(), java.util.Map.of(), Instant.now());
        assertEquals("AI: offline templates", DashboardPresenter.statusItems(empty).get(1));
        assertEquals("Live monitors: none configured", DashboardPresenter.statusItems(empty).get(2));
    }

    private static void save(FindingRepository repo, long session, String target, int score) throws Exception {
        Finding f = new Finding("t", target, "NET-001", score, "x");
        f.setSessionId(session);
        repo.save(f);
    }

    @Test
    void feedStatusText() {
        var fresh = new com.aegislens.intel.FeedUpdater.Status("spamhaus-drop", true, 900, Instant.parse("2026-10-30T06:00:00Z"), false, null, "x");
        var stale = new com.aegislens.intel.FeedUpdater.Status("feodo-c2", true, 0, Instant.parse("2026-10-26T06:00:00Z"), true, "offline", "x");
        var off = new com.aegislens.intel.FeedUpdater.Status("other", false, 0, null, false, null, "x");
        assertEquals("Threat feeds: off", DashboardPresenter.feedText(List.of(off)));
        assertEquals("Threat feeds: 1 fresh", DashboardPresenter.feedText(List.of(fresh, off)));
        assertEquals("Threat feeds: 1 of 2 stale (last update 2026-10-30)", DashboardPresenter.feedText(List.of(fresh, stale)));
    }

    @Test
    void chartsHaveASpokenSummary() {
        Map<String, Integer> modules = new java.util.LinkedHashMap<>();
        modules.put("INTRUSION", 6);
        modules.put("MALWARE", 4);
        assertEquals("Findings by module: Intrusion 6, Malware 4", DashboardPresenter.spoken("Findings by module", modules));
        assertEquals("Findings by module: none", DashboardPresenter.spoken("Findings by module", Map.<String, Long>of()));
    }

    @Test
    void criticalNoticeTextIsShortAndCleaned() {
        Finding f = new Finding("ssh", "203.0.113.45", "NET-001", 95, "Brute force ‮exe.pdf");
        assertEquals("New CRITICAL finding: NET-001 on 203.0.113.45: Brute force exe.pdf", CriticalToast.message(1, f));
        assertTrue(CriticalToast.message(5, f).startsWith("5 new CRITICAL findings, latest: NET-001"));
    }
}
