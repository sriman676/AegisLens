package com.aegislens.app;

import com.aegislens.TestWait;
import com.aegislens.core.Finding;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.IocRepository;
import com.aegislens.db.RuleRepository;
import com.aegislens.intrusion.DetectionEngine;
import com.aegislens.intrusion.LogType;
import com.aegislens.intrusion.Thresholds;
import com.aegislens.util.CidrSet;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** Sample logs through the real pipeline (detectors, allow-list, dedupe, database), and rule-table thresholds. */
class IntrusionPipelineTest {

    private static final AppConfig UTC = config("--oddhour.zone=UTC");

    @Test
    void sampleLogsEndUpInTheDatabase() throws Exception {
        try (Database db = Database.inMemory()) {
            ScanCoordinator c = new ScanCoordinator(db, UTC);
            c.start();
            DetectionEngine.ReplayResult auth = c.replayLog(Path.of("sample-data", "auth.log"), LogType.SSH).get(30, TimeUnit.SECONDS);
            DetectionEngine.ReplayResult web = c.replayLog(Path.of("sample-data", "access.log"), LogType.WEB).get(30, TimeUnit.SECONDS);
            c.shutdown();
            assertEquals(0, auth.malformed() + web.malformed());

            List<Finding> saved = new FindingRepository(db).findRecent(100);
            assertTrue(has(saved, "NET-001", 90), "I1 escalation reached the database");
            assertTrue(has(saved, "NET-001", 60), "the first alert too (different severity, so not a duplicate)");
            assertTrue(has(saved, "NET-003", 35));
            assertTrue(has(saved, "NET-002", 55));
            assertTrue(has(saved, "WEB-002", 70));
            assertEquals(1, saved.stream().filter(f -> f.ruleId().equals("WEB-002")).count(),
                    "the second injection from the same IP is a duplicate inside the cooldown");
            List<Finding> benign = saved.stream().filter(f -> f.target().startsWith("198.51.100.")).toList();
            assertTrue(benign.isEmpty(), "I6 (also across both logs in one engine): " + benign);
        }
    }

    @Test
    void liveTailingReachesTheDatabaseAndARestartDoesNotReAlert(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        Path log = dir.resolve("auth.log");
        java.nio.file.Files.writeString(log, "");
        AppConfig cfg = config("--oddhour.zone=UTC", "--monitor.ssh.files=" + log, "--monitor.silence.minutes=0");
        try (Database db = Database.open(dir.resolve("live.db"))) {
            ScanCoordinator first = new ScanCoordinator(db, cfg);
            first.start();
            TestWait.until(() -> first.monitorStatus().get(0).state().equals("TIMED_WAITING"), "condition");
            StringBuilder attack = new StringBuilder();
            for (int i = 0; i < 6; i++) {
                attack.append("Oct 21 02:14:0").append(i).append(" srv sshd[1]: Failed password for root from 203.0.113.99 port 1 ssh2\n");
            }
            java.nio.file.Files.writeString(log, attack.toString(), java.nio.file.StandardOpenOption.APPEND);
            FindingRepository findings = new FindingRepository(db);
            TestWait.until(() -> count(findings) == 1, "condition");
            first.shutdown();

            ScanCoordinator second = new ScanCoordinator(db, cfg);       // same database: offsets come from log_offset
            second.start();
            Thread.sleep(1_500);
            second.shutdown();
            assertEquals(1, count(findings), "the restart continued after the saved offset");
        }
    }

    private static int count(FindingRepository repo) {
        try {
            return repo.count();
        } catch (java.sql.SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void thresholdsComeFromTheRuleTable() throws Exception {
        try (Database db = Database.inMemory()) {
            RuleRepository rules = new RuleRepository(db);
            rules.setThreshold("NET-001", 8);
            rules.setEnabled("NET-003", false);
            Thresholds t = IntrusionSetup.thresholds(rules, config("--oddhour.start=22:00", "--oddhour.end=06:00", "--oddhour.zone=UTC"));
            assertEquals(8, t.bruteForceFailures());
            assertFalse(t.enabled("NET-003"));
            assertEquals("22:00", t.quietStart().toString());
            assertTrue(t.scannerAgentPattern().contains("sqlmap"), "pattern from the seed rule");
        }
    }

    @Test
    void threatIntelSetsComeFromTheIocTable() throws Exception {
        try (Database db = Database.inMemory()) {
            IocRepository iocs = new IocRepository(db);
            iocs.addAll("CIDR", List.of("198.51.100.0/24"), "spamhaus-drop");
            iocs.addAll("IP", List.of("203.0.113.66"), "feodo-c2");
            CidrSet[] sets = IntrusionSetup.threatIntel(iocs);
            assertTrue(sets[0].contains("198.51.100.200"));
            assertTrue(sets[1].contains("203.0.113.66"));
            assertFalse(sets[0].contains("203.0.113.66"));
        }
    }

    private static boolean has(List<Finding> all, String rule, int score) {
        return all.stream().anyMatch(f -> f.ruleId().equals(rule) && f.score() == score);
    }

    private static AppConfig config(String... args) {
        try {
            return AppConfig.load(null, Map.of(), args);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
