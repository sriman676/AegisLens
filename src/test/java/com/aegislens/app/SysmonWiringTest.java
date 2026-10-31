package com.aegislens.app;

import com.aegislens.TestWait;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.IocRepository;
import com.aegislens.intrusion.LogType;
import com.aegislens.ui.IntrusionPresenter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * A Sysmon export replayed through the real app: the real threat lists (an own indicator) and the real look-alike
 * checker are used, and every finding lands in the HOST module.
 */
class SysmonWiringTest {

    @TempDir
    Path dir;

    /** Loads SQLite's native library outside the temp folder (see HeadlessMainTest). */
    @BeforeAll
    static void loadSqlite() throws Exception {
        Database.inMemory().close();
    }

    @Test
    void sampleExportGivesEveryHostRuleInTheHostModule() throws Exception {
        ScanCoordinator c = new ScanCoordinator(AppConfig.load(null, Map.of(),
                new String[] {"--data.dir=" + dir.resolve("data"), "--feeds.enabled=false"}));
        c.start();
        try {
            new IocRepository(c.database()).addAll("IP", List.of("203.0.113.66"), "manual");
            Path sample = Path.of("sample-data", "sysmon-sample.xml");
            assertEquals(LogType.SYSMON_XML, IntrusionPresenter.guessType(sample.getFileName().toString()));
            assertEquals(9, c.replayLog(sample, LogType.SYSMON_XML).get(30, TimeUnit.SECONDS).findings());

            FindingRepository findings = new FindingRepository(c.database());
            TestWait.until(() -> rules(findings).size() == 9, "all nine host findings saved");
            assertEquals(Set.of("HOST"), findings.countByModule().keySet(), "Sysmon findings are HOST, not INTRUSION");
            assertTrue(findings.findByRule("HOST-006", 1).get(0).description().contains("paypal"),
                    "the real look-alike checker recognised paypa1");
            assertTrue(findings.topTargets(10).isEmpty(), "program names never show up as 'top attackers'");
        } finally {
            c.shutdown();
        }
    }

    @Test
    void overlappingExportsInTheWatchedFolderAreReadOnce() throws Exception {
        ScanCoordinator c = new ScanCoordinator(AppConfig.load(null, Map.of(),
                new String[] {"--data.dir=" + dir.resolve("data2"), "--feeds.enabled=false"}));
        c.start();
        try {
            Path sample = Path.of("sample-data", "sysmon-sample.xml");
            assertEquals(8, c.replaySysmonExport(sample).get(30, TimeUnit.SECONDS).findings(), "first export: all new");
            assertEquals(0, c.replaySysmonExport(sample).get(30, TimeUnit.SECONDS).findings(),
                    "the next export holds the same events: nothing is reported twice");
            assertEquals(8, c.replayLog(sample, LogType.SYSMON_XML).get(30, TimeUnit.SECONDS).findings(),
                    "a replay you ask for still reads the whole file");
        } finally {
            c.shutdown();
        }
    }

    private static Set<String> rules(FindingRepository findings) {
        try {
            return findings.findRecent(100).stream().map(f -> f.ruleId()).collect(Collectors.toSet());
        } catch (SQLException e) {
            return Set.of();
        }
    }
}
