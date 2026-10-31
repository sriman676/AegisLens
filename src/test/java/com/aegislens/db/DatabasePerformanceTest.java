package com.aegislens.db;

import com.aegislens.core.Finding;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Measures the performance targets on a real file database and prints the numbers:
 * 10 000 findings in batches under 2 s, dashboard query under 50 ms on 1 million rows, reads not stuck behind the writer.
 * Slow, so excluded from the normal build: mvn test -Dgroups=perf -DexcludedGroups=none
 * Known results (Windows 11, JDK 26):
 * - 2026-10-29, schema v2: writes 507 ms, reads-while-writing 26 ms, dashboard 164 ms (FAILED the 50 ms target).
 * - 2026-10-30, schema v3 (R18): dashboard 0 ms (it reads the trigger-maintained finding_counts table), reads-while-writing
 *   31 ms; writes 1370 ms, slower because every insert also updates finding_counts and the FTS5 index (still under 2 s).
 */
@Tag("perf")
class DatabasePerformanceTest {

    private static final int BATCH = 200;
    private static final long WRITE_TARGET_MS = 2_000;
    private static final long DASHBOARD_TARGET_MS = 50;
    private static final long READ_WAIT_TARGET_MS = 100;
    private static final int MILLION = 1_000_000;

    @TempDir
    Path dir;

    @Test
    void tenThousandFindingsInBatches() throws Exception {
        try (Database db = Database.open(dir.resolve("w.db"))) {
            long session = new ScanSessionRepository(db).begin("INTRUSION", "perf");
            FindingRepository repo = new FindingRepository(db);
            long start = System.nanoTime();
            for (int b = 0; b < 10_000 / BATCH; b++) {
                repo.saveAll(findings(session, BATCH));
            }
            long ms = (System.nanoTime() - start) / 1_000_000;
            System.out.println("[perf] 10 000 findings in batches of " + BATCH + ": " + ms + " ms (target < " + WRITE_TARGET_MS + ")");
            assertEquals(10_000, repo.count());
            assertTrue(ms < WRITE_TARGET_MS, ms + " ms");
        }
    }

    @Test
    void dashboardOnOneMillionRowsAndReadsWhileWriting() throws Exception {
        try (Database db = Database.open(dir.resolve("m.db"))) {
            long session = new ScanSessionRepository(db).begin("INTRUSION", "perf");
            fillFast(db, session, MILLION);
            FindingRepository repo = new FindingRepository(db);
            repo.countBySeverity();                                    // warm the page cache once
            long start = System.nanoTime();
            repo.countBySeverity();
            long dashboardMs = (System.nanoTime() - start) / 1_000_000;
            System.out.println("[perf] countBySeverity on " + MILLION + " rows: " + dashboardMs + " ms (target < " + DASHBOARD_TARGET_MS + ")");

            long worstReadMs = worstReadWhileWriting(db, repo, session);
            System.out.println("[perf] slowest read while the writer was busy: " + worstReadMs + " ms (target < " + READ_WAIT_TARGET_MS + ")");

            assertTrue(dashboardMs < DASHBOARD_TARGET_MS, dashboardMs + " ms");
            assertTrue(worstReadMs < READ_WAIT_TARGET_MS, worstReadMs + " ms");
        }
    }

    /** A writer thread saves batches while this thread times findPage + count reads on the reader connection. */
    private static long worstReadWhileWriting(Database db, FindingRepository repo, long session) throws Exception {
        AtomicLong failures = new AtomicLong();
        Thread writer = new Thread(() -> {
            try {
                for (int b = 0; b < 50; b++) {
                    repo.saveAll(findings(session, BATCH));
                }
            } catch (Exception e) {
                failures.incrementAndGet();
            }
        }, "perf-writer");
        writer.start();
        long worst = 0;
        while (writer.isAlive()) {
            long start = System.nanoTime();
            repo.findPage(Long.MAX_VALUE, 50);
            worst = Math.max(worst, (System.nanoTime() - start) / 1_000_000);
        }
        writer.join();
        assertEquals(0, failures.get());
        return worst;
    }

    /** Inserts n rows in one transaction with one reused PreparedStatement (setup only, not a measured path). */
    private static void fillFast(Database db, long session, int n) throws Exception {
        String[] severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"};
        String[] statuses = {"OPEN", "OPEN", "OPEN", "RESOLVED", "FALSE_POSITIVE"};
        db.transaction(c -> {
            try (PreparedStatement ps = c.prepareStatement("INSERT INTO finding (session_id, source, target, rule_id, severity, "
                    + "score, description, evidence, status, created_at) VALUES (?, 'ssh', ?, 'NET-001', ?, 50, 'x', '{}', ?, ?)")) {
                for (int i = 0; i < n; i++) {
                    ps.setLong(1, session);
                    ps.setString(2, "203.0.113." + (i % 250));
                    ps.setString(3, severities[i % severities.length]);
                    ps.setString(4, statuses[i % statuses.length]);
                    ps.setString(5, "2026-10-29T00:00:00Z");
                    ps.addBatch();
                    if (i % 10_000 == 9_999) {
                        ps.executeBatch();
                    }
                }
                ps.executeBatch();
            }
            return null;
        });
    }

    private static List<Finding> findings(long session, int n) {
        List<Finding> list = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            Finding f = new Finding("ssh", "203.0.113." + (i % 250), "NET-001", 40 + (i % 60), "perf " + i);
            f.setSessionId(session);
            list.add(f);
        }
        return list;
    }
}
