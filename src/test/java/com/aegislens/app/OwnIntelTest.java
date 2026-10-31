package com.aegislens.app;

import com.aegislens.core.Finding;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.IocRepository;
import com.aegislens.intel.FeedCatalog;
import com.aegislens.intel.FeedDefinition;
import com.aegislens.intrusion.LogType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** Customisation: your own indicators and feeds. */
class OwnIntelTest {

    @TempDir
    Path dir;

    @Test
    void valuesAreCheckedAndNormalised() throws Exception {
        assertEquals("2001:db8:0:0:0:0:0:1", OwnIntel.normalise("IP", " 2001:db8::1 "));
        assertEquals("a".repeat(64), OwnIntel.normalise("HASH", "A".repeat(64)));
        assertEquals("xn--pypal-4ve.com", OwnIntel.normalise("DOMAIN", "pаypal.com"), "a Cyrillic look-alike becomes punycode");
        assertEquals("https://x.example/login", OwnIntel.normalise("URL", "https://x.example/a/../login"));
        for (String[] bad : new String[][] {{"IP", "10.0.0.256"}, {"CIDR", "203.0.113.5"}, {"HASH", "d41d8cd98f00b204e9800998ecf8427e"},
                {"DOMAIN", "not a domain"}, {"URL", "javascript:alert(1)"}, {"IP", " "}}) {
            assertThrows(AnalystActions.RefusedException.class, () -> OwnIntel.normalise(bad[0], bad[1]), bad[0] + " " + bad[1]);
        }
    }

    @Test
    void anOwnBotnetAddressIsDetectedLiveAndFeedEntriesAreProtected() throws Exception {
        try (Database db = Database.inMemory()) {
            ScanCoordinator c = new ScanCoordinator(db, AppConfig.load(null, Map.of(), new String[] {"--oddhour.zone=UTC"}));
            c.start();
            try {
                OwnIntel own = new OwnIntel(c);
                own.add("IP", "203.0.113.45", true, "seen in our honeypot");
                assertEquals(1, own.list().size());
                assertEquals("seen in our honeypot", own.list().get(0).note());

                c.replayLog(Path.of("sample-data", "auth.log"), LogType.SSH).get(30, TimeUnit.SECONDS);
                FindingRepository findings = new FindingRepository(db);
                long deadline = System.nanoTime() + 10_000_000_000L;
                while (findings.findRecent(100).stream().noneMatch(f -> f.ruleId().equals("NET-005"))) {
                    assertTrue(System.nanoTime() < deadline, "NET-005 was not raised for the own C2 entry");
                    Thread.sleep(50);
                }
                Finding hit = findings.findRecent(100).stream().filter(f -> f.ruleId().equals("NET-005")).findFirst().orElseThrow();
                assertEquals(90, hit.score(), "marked as a botnet controller");

                IocRepository iocs = new IocRepository(db);
                iocs.addAll("IP", List.of("198.51.100.9"), "spamhaus-drop");
                long feedId = iocs.findBySources("spamhaus-drop", "x").get(0).id();
                assertFalse(own.remove(feedId), "feed entries cannot be removed by hand");
                assertTrue(own.remove(own.list().get(0).id()));
                assertTrue(own.list().isEmpty());
            } finally {
                c.shutdown();
            }
        }
    }

    @Test
    void ownFeedsAreCheckedLikeTheBundledOnesAndCanBeTurnedOffOrRemoved() throws Exception {
        assertThrows(AnalystActions.RefusedException.class,
                () -> OwnIntel.addFeed(dir, "lab", "http://x.example/list.txt", "ip-lines", "IP", "Lab list"), "https only");
        assertThrows(AnalystActions.RefusedException.class,
                () -> OwnIntel.addFeed(dir, "Bad Name!", "https://x.example/list.txt", "ip-lines", "IP", ""));
        OwnIntel.addFeed(dir, "lab", "https://x.example/list.txt", "ip-lines", "IP", "Our lab list");
        OwnIntel.setFeedEnabled(dir, "spamhaus-drop", false);
        List<FeedDefinition> feeds = FeedCatalog.load(dir);
        assertTrue(feeds.stream().anyMatch(f -> f.name().equals("lab") && f.enabled()));
        assertTrue(feeds.stream().anyMatch(f -> f.name().equals("spamhaus-drop") && !f.enabled()), "a bundled feed turned off");
        assertTrue(OwnIntel.removeFeed(dir, "lab"));
        assertFalse(OwnIntel.removeFeed(dir, "feodo-c2"), "a bundled feed can only be turned off");
        assertTrue(FeedCatalog.load(dir).stream().noneMatch(f -> f.name().equals("lab")));
        assertTrue(Files.readString(dir.resolve(FeedCatalog.FILE_NAME)).startsWith("# Your feeds"));
    }
}
