package com.aegislens.app;

import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.intel.FeedUpdater;
import com.aegislens.intel.VirusTotalClient;
import com.aegislens.intrusion.LogType;
import com.aegislens.malware.ScanResult;
import com.aegislens.net.FakeServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** R7 end to end: a feed from a (fake) server reaches the live detectors; VirusTotal is off without a key. */
class ThreatIntelWiringTest {

    @TempDir
    Path dir;

    @Test
    void feedUpdateFeedsLiveDetection() throws Exception {
        try (FakeServer s = FakeServer.http(Map.of("/c2.txt", ex -> FakeServer.reply(ex, 200, "# botnet C2\n203.0.113.45\n")))) {
            Path data = Files.createDirectories(dir.resolve("data"));
            Files.writeString(data.resolve("feeds.properties"), String.join("\n",
                    "feed.spamhaus-drop.enabled=false",
                    "feed.feodo-c2.enabled=false",
                    "feed.test-c2.url=" + s.base() + "/c2.txt",
                    "feed.test-c2.allow.http=true",
                    "feed.test-c2.format=ip-lines",
                    "feed.test-c2.kind=IP",
                    "feed.test-c2.enabled=true",
                    "feed.test-c2.c2=true",
                    "feed.test-c2.min.interval.minutes=1",
                    "feed.test-c2.attribution=test feed", ""));
            AppConfig cfg = AppConfig.load(null, Map.of(), new String[] {"--data.dir=" + data, "--oddhour.zone=UTC",
                    "--monitor.silence.minutes=0", "--feeds.enabled=false"});
            try (Database db = Database.open(dir.resolve("t.db"))) {
                ScanCoordinator c = new ScanCoordinator(db, cfg);
                c.start();
                try {
                    List<FeedUpdater.Result> results = c.updateFeedsNow().get(30, TimeUnit.SECONDS);
                    assertEquals(1, results.size(), "only the enabled test feed");
                    assertEquals(FeedUpdater.Outcome.UPDATED, results.get(0).outcome());
                    assertEquals(1, c.feedStatus().stream().filter(st -> st.feed().equals("test-c2")).findFirst().orElseThrow().entries());

                    c.replayLog(Path.of("sample-data", "auth.log"), LogType.SSH).get(30, TimeUnit.SECONDS);
                    FindingRepository repo = new FindingRepository(db);
                    long deadline = System.nanoTime() + 10_000_000_000L;
                    while (repo.findRecent(100).stream().noneMatch(f -> f.ruleId().equals("NET-005"))) {
                        assertTrue(System.nanoTime() < deadline, "NET-005 not raised");
                        Thread.sleep(50);
                    }
                    assertEquals(90, repo.findRecent(100).stream().filter(f -> f.ruleId().equals("NET-005"))
                            .findFirst().orElseThrow().score(), "a C2 list hit scores 90");

                    assertFalse(c.virusTotalEnabled(), "no VT_API_KEY in tests");
                    ScanResult r = new ScanResult("x", null, "PE", 1, "m", "a".repeat(64), 1, 0, List.of(), Map.of(), null);
                    ExecutionException e = assertThrows(ExecutionException.class, () -> c.checkVirusTotal(r).get(5, TimeUnit.SECONDS));
                    assertEquals(VirusTotalClient.VtException.Kind.NOT_CONFIGURED, ((VirusTotalClient.VtException) e.getCause()).kind());
                } finally {
                    c.shutdown();
                }
            }
        }
    }
}
