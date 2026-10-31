package com.aegislens.app;

import com.aegislens.ai.ExplanationService;
import com.aegislens.core.Finding;
import com.aegislens.core.Severity;
import com.aegislens.db.AiExplanationRepository;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.ScanSessionRepository;
import com.aegislens.net.FakeServer;
import com.aegislens.net.RetryPolicy;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** Webhook notifier, DB explanation cache and the coordinator's explain path (offline, no keys). */
class ConnectivityWiringTest {

    @TempDir
    Path dir;

    @Test
    void webhookSendsOnlyImportantFindingsWithoutRawLines() throws Exception {
        List<String> bodies = Collections.synchronizedList(new ArrayList<>());
        try (FakeServer s = FakeServer.http(Map.of("/hook", ex -> {
            bodies.add(FakeServer.body(ex));
            FakeServer.reply(ex, 204, "");
        }))) {
            WebhookNotifier hook = new WebhookNotifier(URI.create(s.base() + "/hook"), Severity.HIGH, true,
                    HttpClient.newHttpClient(), new RetryPolicy(2, Duration.ZERO, d -> { }, new Random()));
            hook.offer(new Finding("ssh", "203.0.113.45", "NET-001", 90, "login after brute force",
                    Map.of("failures", "7", "line", "Oct 21 sshd[1]: Accepted password for root"), null));
            hook.offer(new Finding("ssh", "198.51.100.1", "NET-003", 35, "odd hour login"));     // MEDIUM: not sent
            long deadline = System.nanoTime() + 5_000_000_000L;
            while (hook.sentCount() < 1) {
                assertTrue(System.nanoTime() < deadline, "webhook not delivered");
                Thread.sleep(20);
            }
            Thread.sleep(200);
            hook.close();
            assertEquals(1, bodies.size());
            String text = new ObjectMapper().readTree(bodies.get(0)).path("text").asText();
            assertTrue(text.startsWith("[AegisLens] CRITICAL 90 NET-001 203.0.113.45"));
            assertTrue(text.contains("failures=7"));
            assertFalse(text.contains("Accepted password"), "raw log lines are never sent");
        }
        assertThrows(IllegalArgumentException.class, () -> new WebhookNotifier(URI.create("http://hooks.example/x"),
                Severity.HIGH, false, HttpClient.newHttpClient(), RetryPolicy.none()), "plain http is refused by default");
        String long1 = "x".repeat(5_000);
        assertTrue(WebhookNotifier.payload(new Finding("t", "t", "R", 90, long1)).length() < 1_100, "capped at 1 000 characters");
        assertEquals("https://hooks.example.com/…ab12", WebhookNotifier.mask(URI.create("https://hooks.example.com/services/T0/B0/secretab12")));
    }

    @Test
    void coordinatorExplainsOfflineAndTheCacheIsTheDatabase() throws Exception {
        try (Database db = Database.inMemory()) {
            long session = new ScanSessionRepository(db).begin("INTRUSION", "x");
            Finding f = new Finding("ssh", "203.0.113.45", "NET-001", 72, "7 failed logins");
            f.setSessionId(session);
            new FindingRepository(db).save(f);
            ScanCoordinator c = new ScanCoordinator(db, AppConfig.load(null, Map.of(), new String[] {"--data.dir=" + dir}));
            c.start();
            try {
                ExplanationService.Explanation e = c.explain(f, ExplanationService.AUTO).get(10, TimeUnit.SECONDS);
                assertEquals("offline", e.provider(), "no keys and no local model configured");
                assertFalse(e.fellBack(), "nothing was tried, so nothing fell back");
                assertTrue(e.text().contains("brute force"));
                assertTrue(c.connectivityStatus().isEmpty(), "no cloud AI configured: nothing to monitor");
                assertTrue(c.webhookTarget().isEmpty());
                assertEquals(List.of("offline"), c.explanations().providerNames());

                DbExplanationCache cache = new DbExplanationCache(new AiExplanationRepository(db));
                cache.store(f.id(), "claude", "cached answer");
                assertEquals("cached answer", cache.find(f.id(), "claude").orElseThrow());
                assertTrue(cache.find(f.id(), "gemini").isEmpty());
            } finally {
                c.shutdown();
            }
        }
    }
}
