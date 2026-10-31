package com.aegislens.app;

import com.aegislens.ai.ExplanationService;
import com.aegislens.core.Finding;
import com.aegislens.db.BlockedIpRepository;
import com.aegislens.db.DataExchange;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.FindingSearch;
import com.aegislens.intrusion.LogType;
import com.aegislens.malware.ScanResult;
import com.aegislens.response.BlocklistExporter;
import com.aegislens.response.HtmlReportExporter;
import com.aegislens.sandbox.DemoProgram;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * P7 integration: one analyst session through the real app, module after module, on a throw-away data folder:
 * replay -> scan -> URL check -> sandbox -> explain -> record block -> export blocklist, report and CSV -> re-import.
 */
class EndToEndTest {

    @TempDir
    Path dir;

    /** Loads SQLite's native library outside the temp folder (see HeadlessMainTest). */
    @BeforeAll
    static void loadSqlite() throws Exception {
        Database.inMemory().close();
    }

    @Test
    void aWholeAnalystSessionWorksAcrossAllModules() throws Exception {
        AppConfig cfg = AppConfig.load(null, Map.of(), new String[] {"--data.dir=" + dir.resolve("data"),
                "--feeds.enabled=false", "--oddhour.zone=UTC"});
        ScanCoordinator c = new ScanCoordinator(cfg);
        c.start();
        try {
            c.replayLog(Path.of("sample-data", "auth.log"), LogType.SSH).get(30, TimeUnit.SECONDS);
            c.replayLog(Path.of("sample-data", "access.log"), LogType.WEB).get(30, TimeUnit.SECONDS);
            byte[] packed = new byte[100_000];
            new Random(1).nextBytes(packed);
            ScanResult scan = c.scanFile(Files.write(dir.resolve("packed.bin"), packed)).get(30, TimeUnit.SECONDS);
            assertTrue(scan.risk() >= 50, "random bytes look packed");
            assertFalse(c.checkUrl("https://g00gle-account-check.example.test/signin", false).get(10, TimeUnit.SECONDS).findings().isEmpty());
            assertEquals(3, c.runDemo(DemoProgram.DROPPER).get(60, TimeUnit.SECONDS).report().createdFiles().size());

            FindingRepository findings = new FindingRepository(c.database());
            long deadline = System.nanoTime() + 15_000_000_000L;
            while (modules(findings).size() < 4) {
                assertTrue(System.nanoTime() < deadline, "findings from every module: " + modules(findings));
                Thread.sleep(100);
            }
            assertEquals(Set.of("INTRUSION", "MALWARE", "WEB", "SANDBOX"), modules(findings));

            ScanResult saved = c.recentScans(10).stream().filter(r -> r.name().equals("packed.bin")).findFirst().orElseThrow();
            assertEquals(scan.risk(), saved.risk(), "the Malware view gets earlier scans back after a restart");
            assertFalse(saved.findings().isEmpty(), "with their findings");

            Finding brute = findings.findRecent(200).stream().filter(f -> f.ruleId().equals("NET-001")).findFirst().orElseThrow();
            ExplanationService.Explanation e = c.explain(brute, ExplanationService.AUTO).get(10, TimeUnit.SECONDS);
            assertFalse(e.text().isBlank(), "offline explanation without any key");

            AnalystActions actions = new AnalystActions(c);
            actions.recordBlock(brute.target(), "end-to-end");
            BlocklistExporter.Result block = new BlocklistExporter(AllowList.parse(""))
                    .export(new BlockedIpRepository(c.database()).findAll(), dir.resolve("blocklist"), Instant.now());
            assertEquals(1, block.written());
            assertTrue(Files.readString(dir.resolve("blocklist").resolve("blocklist.txt")).contains(brute.target()));

            Path report = dir.resolve("report.html");
            assertTrue(new HtmlReportExporter(c.database()).export(report, Instant.now(), Branding.load(c)) > 0);
            Path csv = dir.resolve("findings.csv");
            int exported = new DataExchange(c.database()).export(FindingSearch.Filter.ALL, csv, DataExchange.Format.CSV);
            try (Database fresh = Database.inMemory()) {
                assertEquals(exported, new DataExchange(fresh).importCsv(csv), "the export can be read back");
            }
        } finally {
            c.shutdown();
        }
    }

    private static Set<String> modules(FindingRepository findings) throws Exception {
        return findings.countByModule().keySet().stream().collect(Collectors.toSet());
    }
}
