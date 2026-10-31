package com.aegislens.app;

import com.aegislens.db.Database;
import com.aegislens.db.RuleRepository;
import com.aegislens.malware.ScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** Customisation: rule on/off and thresholds changed in Settings apply to the next event and the next scan. */
class LiveRulesTest {

    @TempDir
    Path dir;

    @Test
    void ruleChangesApplyWithoutARestart() throws Exception {
        byte[] random = new byte[64 * 1024];
        new Random(7).nextBytes(random);                       // entropy just under 8.0: MAL-001 territory
        Path packed = Files.write(dir.resolve("packed.bin"), random);
        try (Database db = Database.inMemory()) {
            ScanCoordinator c = new ScanCoordinator(db, AppConfig.defaults());
            c.start();
            try {
                RuleRepository rules = new RuleRepository(db);
                int all = c.engine().detectorCount();
                assertTrue(hasRule(c, packed, "MAL-001"), "default: packed data is flagged");

                rules.setEnabled("MAL-001", false);
                rules.setEnabled("NET-001", false);
                c.reloadRules();
                assertFalse(hasRule(c, packed, "MAL-001"), "switched off: not reported");
                assertEquals(all - 1, c.engine().detectorCount(), "the brute-force detector was removed live");

                rules.setEnabled("MAL-001", true);
                rules.setThreshold("MAL-001", 8.0);           // nothing real reaches 8.0 bits
                rules.setEnabled("NET-001", true);
                c.reloadRules();
                assertFalse(hasRule(c, packed, "MAL-001"), "a higher threshold is used by the next scan");
                assertEquals(all, c.engine().detectorCount());
            } finally {
                c.shutdown();
            }
        }
    }

    private static boolean hasRule(ScanCoordinator c, Path file, String rule) throws Exception {
        ScanResult r = c.scanFile(file).get(30, TimeUnit.SECONDS);
        return r.findings().stream().anyMatch(f -> f.ruleId().equals(rule));
    }
}
