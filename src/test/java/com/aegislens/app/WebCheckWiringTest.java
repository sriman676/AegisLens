package com.aegislens.app;

import com.aegislens.core.Finding;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.RuleRepository;
import com.aegislens.ui.WebPresenter;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** R9 wiring: URL findings go through the normal pipeline; own domains count as a threat list; rules can be off. */
class WebCheckWiringTest {

    @Test
    void urlFindingsAreSavedOwnDomainsMatchAndDisabledRulesAreDropped() throws Exception {
        try (Database db = Database.inMemory()) {
            ScanCoordinator c = new ScanCoordinator(db, AppConfig.defaults());
            c.start();
            try {
                new OwnIntel(c).add("DOMAIN", "bad-site.example.test", false, "phishing kit");
                ScanCoordinator.WebCheck w = c.checkUrl("https://bad-site.example.test/x", false).get(10, TimeUnit.SECONDS);
                assertEquals(List.of("WEB-004"), w.findings().stream().map(Finding::ruleId).toList());

                ScanCoordinator.WebCheck look = c.checkUrl("https://g00gle-account-check.example.test/signin", false).get(10, TimeUnit.SECONDS);
                assertTrue(look.findings().get(0).score() >= 75);
                FindingRepository findings = new FindingRepository(db);
                long deadline = System.nanoTime() + 10_000_000_000L;
                while (findings.count() < 2) {
                    assertTrue(System.nanoTime() < deadline, "findings were not saved");
                    Thread.sleep(50);
                }
                assertEquals(Map.of("WEB", 2), findings.countByModule());

                new RuleRepository(db).setEnabled("WEB-001", false);
                c.reloadRules();
                assertTrue(c.checkUrl("https://g00gle-account-check.example.test/signin", false).get(10, TimeUnit.SECONDS)
                        .findings().isEmpty(), "a switched-off rule is not reported");
            } finally {
                c.shutdown();
            }
        }
    }

    @Test
    void presenterTexts() {
        Finding f = new Finding("web", "u", "WEB-001", 75, "Phishing indicators", Map.of("lookalike", "imitates paypal.com",
                "note-words", "asks to 'login'"), null);
        assertEquals("Suspicious: HIGH (score 75)", WebPresenter.verdict(List.of(f)));
        Finding critical = new Finding("web", "u", "WEB-004", 90, "on a list");
        assertEquals("Suspicious: CRITICAL (score 90)", WebPresenter.verdict(List.of(f, critical)), "the worst comes first");
        assertEquals("No warning signs found", WebPresenter.verdict(List.of()));
        assertTrue(WebPresenter.reasons(f).contains("    note: asks to 'login'"));
        assertEquals(List.of("a.test", "b.test"), WebPresenter.addresses(List.of("# list", " a.test ", "", "b.test")));
    }
}
