package com.aegislens.ai;

import com.aegislens.ai.LlmException.Kind;
import com.aegislens.core.Finding;
import com.aegislens.net.FakeServer;
import com.aegislens.net.HttpClientFactory;
import com.aegislens.net.RetryPolicy;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/** R8/R16: typed errors, tolerant parsing, local model, SplitShield over pinned HTTPS, redaction, budget, cache, tiers. */
class AiConnectivityTest {

    private static final RetryPolicy FAST = new RetryPolicy(3, Duration.ZERO, d -> { }, new Random(1));
    private final HttpClient client = HttpClient.newHttpClient();
    private final Finding finding = new Finding("ssh", "203.0.113.45", "NET-001", 72, "7 failed logins for root from 203.0.113.45",
            Map.of("user", "root", "failures", "7", "line", "Oct 21 sshd: Failed password for root"), null);

    @Test
    void httpStatusesBecomeTypedErrors() throws Exception {
        Map<String, Integer> status = new HashMap<>(Map.of("s", 401));
        try (FakeServer s = FakeServer.http(Map.of("/v1/messages", ex -> FakeServer.reply(ex, status.get("s"), "{}")))) {
            assertEquals(Kind.AUTH, kind(() -> claude(s).explain(finding)));
            status.put("s", 404);
            assertEquals(Kind.MODEL_NOT_FOUND, kind(() -> claude(s).explain(finding)));
            status.put("s", 429);
            assertEquals(Kind.RATE_LIMIT, kind(() -> claude(s).explain(finding)));
            status.put("s", 503);
            assertEquals(Kind.SERVER, kind(() -> claude(s).explain(finding)));
            assertEquals(Kind.NOT_CONFIGURED, kind(() -> new ClaudeProvider("", "m", s.base(), "v", client, FAST).explain(finding)));
        }
        assertEquals(Kind.NETWORK, kind(() -> new ClaudeProvider("k", "m", "http://127.0.0.1:1/v1/messages", "v", client, FAST).explain(finding)));
    }

    @Test
    void repliesAreParsedTolerantly() throws Exception {
        AtomicReference<String> reply = new AtomicReference<>("not json at all");
        try (FakeServer s = FakeServer.http(Map.of("/v1/messages", ex -> FakeServer.reply(ex, 200, reply.get()),
                "/v1beta/models/m:generateContent", ex -> FakeServer.reply(ex, 200, reply.get())))) {
            assertEquals(Kind.BAD_RESPONSE, kind(() -> claude(s).explain(finding)));
            reply.set("{\"content\":[],\"stop_reason\":\"refusal\"}");
            assertEquals(Kind.BLOCKED, kind(() -> claude(s).explain(finding)));
            reply.set("{\"content\":[{\"type\":\"text\",\"text\":\"Partial\"}],\"stop_reason\":\"max_tokens\"}");
            assertTrue(claude(s).explain(finding).contains("cut short"));
            reply.set("{\"candidates\":[]}");
            assertEquals(Kind.BLOCKED, kind(() -> new GeminiProvider("k", "m", s.base(), client, FAST).explain(finding)));
            reply.set("{\"pad\":\"" + "z".repeat(1_100_000) + "\"}");
            assertEquals(Kind.BAD_RESPONSE, kind(() -> claude(s).explain(finding)), "a reply over 1 MB is refused");
        }
    }

    @Test
    void localOpenAiCompatibleModel() throws Exception {
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<String> auth = new AtomicReference<>();
        try (FakeServer s = FakeServer.http(Map.of("/v1/chat/completions", ex -> {
            body.set(FakeServer.body(ex));
            auth.set(ex.getRequestHeaders().getFirst("authorization"));
            FakeServer.reply(ex, 200, "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"Local says: block it.\"},\"finish_reason\":\"stop\"}]}");
        }))) {
            OpenAiCompatibleProvider local = new OpenAiCompatibleProvider(s.base() + "/v1/", "llama3.2:3b", "", client, FAST);
            assertEquals("Local says: block it.", local.explain(finding));
            assertTrue(body.get().contains("\"model\":\"llama3.2:3b\""));
            assertTrue(body.get().contains("finding_data"));
            assertTrue(body.get().contains("203.0.113.45"), "local models see the real values (nothing leaves the machine)");
            assertNull(auth.get(), "no key: no Authorization header");
            new OpenAiCompatibleProvider(s.base() + "/v1", "m", "lm-key", client, FAST).explain(finding);
            assertEquals("Bearer lm-key", auth.get());
        }
    }

    @Test
    void splitShieldOverPinnedHttps() throws Exception {
        AtomicReference<String> query = new AtomicReference<>();
        AtomicReference<String> rows = new AtomicReference<>("{\"understood\":\"events about 203.0.113.45\",\"count\":12,\"rows\":["
                + "{\"time\":\"2026-10-29 14:02:11\",\"source\":\"ssh\",\"kind\":\"failed_login\",\"ip\":\"203.0.113.45\",\"techniques\":\"T1110, T1078\",\"detail\":\"Failed password for root\"},"
                + "{\"time\":\"2026-10-29 13:50:00\",\"source\":\"zeek\",\"kind\":\"scan\",\"ip\":\"203.0.113.45\",\"techniques\":\"T1046\",\"detail\":\"port scan\"}]}");
        try (FakeServer s = FakeServer.https(Map.of("/api/v1/search", ex -> {
            query.set(ex.getRequestURI().getQuery());
            if (!"Bearer good-token".equals(ex.getRequestHeaders().getFirst("authorization"))) {
                FakeServer.reply(ex, 401, "{\"error\":\"unauthorised\"}");
            } else {
                FakeServer.reply(ex, 200, rows.get());
            }
        })); HttpClientFactory http = HttpClientFactory.defaults()) {
            HttpClient pinned = http.pinnedClient(FakeServer.certificatePin());
            String text = new SplitShieldProvider(s.base(), "good-token", pinned, FAST).explain(finding);
            assertTrue(query.get().contains("q=203.0.113.45"));
            assertTrue(text.startsWith("SplitShield-XAI has 12 stored events about 203.0.113.45"), text);
            assertTrue(text.contains("ssh (1), zeek (1)"));
            assertTrue(text.contains("T1110, T1078, T1046"));
            assertTrue(text.contains("Latest: 2026-10-29 14:02:11 failed_login"));

            assertEquals(Kind.AUTH, kind(() -> new SplitShieldProvider(s.base(), "bad", pinned, FAST).explain(finding)));
            int before = s.requests.get();
            assertEquals(Kind.NOT_CONFIGURED, kind(() -> new SplitShieldProvider(s.base(), null, pinned, FAST).explain(finding)));
            assertEquals(before, s.requests.get(), "no token: no request at all");
            assertEquals(Kind.NETWORK, kind(() -> new SplitShieldProvider(s.base(), "good-token",
                    http.pinnedClient("ab".repeat(32)), FAST).explain(finding)), "wrong certificate pin");

            rows.set("{\"understood\":\"x\",\"count\":0,\"rows\":[]}");
            assertEquals("SplitShield-XAI has no stored events about 203.0.113.45.",
                    new SplitShieldProvider(s.base(), "good-token", pinned, FAST).explain(finding));
        }
        Finding file = new Finding("pe", "C:\\Users\\bob\\Downloads\\invoice.exe", "MAL-002", 45, "x");
        assertEquals("invoice.exe", SplitShieldProvider.subject(file));
        assertEquals("root", SplitShieldProvider.subject(new Finding("ssh", "server-1", "NET-003", 35, "x", Map.of("user", "root"), null)));
    }

    @Test
    void redactionHidesPrivateValuesAndMapsThemBack() {
        Redactor r = new Redactor();
        Finding sent = r.redact(new Finding("pe", "C:\\Users\\bob\\Downloads\\invoice.exe", "MAL-002", 45,
                "bob opened it from 198.51.100.7 and 2001:db8::5 at 02:14:20", Map.of("user", "bob", "line", "raw"), null));
        assertEquals("invoice.exe", sent.target());
        assertEquals("USER-1 opened it from IP-1 and IP-2 at 02:14:20", sent.description(), "a time is not an IPv6 address");
        assertFalse(sent.evidence().containsKey("line"), "raw log lines never leave");
        assertEquals("Block 198.51.100.7 and talk to bob.", r.restore("Block IP-1 and talk to USER-1."));
    }

    @Test
    void budgetLimitsCallsPerHourAndDay() {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-30T08:00:00Z"));
        LlmBudget b = new LlmBudget(2, 3, clock);
        assertTrue(b.tryAcquire());
        assertTrue(b.tryAcquire());
        assertFalse(b.tryAcquire(), "hour limit");
        clock.now = clock.now.plus(Duration.ofMinutes(61));
        assertTrue(b.tryAcquire());
        assertFalse(b.tryAcquire(), "day limit (3)");
        assertEquals(new LlmBudget.Usage(1, 2, 3, 3), b.usage());
        clock.now = clock.now.plus(Duration.ofDays(1));
        assertTrue(b.tryAcquire());
    }

    @Test
    void autoWalksTheTiersUsesTheCacheAndRedactsCloudOnly() throws Exception {
        AtomicReference<String> cloudBody = new AtomicReference<>();
        Map<String, Integer> cloudStatus = new HashMap<>(Map.of("s", 200));
        try (FakeServer s = FakeServer.http(Map.of(
                "/v1/messages", ex -> {
                    cloudBody.set(FakeServer.body(ex));
                    FakeServer.reply(ex, cloudStatus.get("s"), "{\"content\":[{\"type\":\"text\",\"text\":\"Cloud: block IP-1 now.\"}]}");
                },
                "/v1/chat/completions", ex -> FakeServer.reply(ex, 200, "{\"choices\":[{\"message\":{\"content\":\"Local answer\"}}]}")))) {
            ExplanationService svc = new ExplanationService();
            svc.register(claude(s));
            svc.register(new OpenAiCompatibleProvider(s.base() + "/v1", "m", null, client, FAST));
            MemoryCache cache = new MemoryCache();
            svc.setCache(cache);
            Finding saved = copyWithId(finding, 42);

            ExplanationService.Explanation first = svc.explain(ExplanationService.AUTO, saved);
            assertEquals("claude", first.provider());
            assertEquals("Cloud: block 203.0.113.45 now.", first.text(), "placeholder mapped back");
            assertTrue(first.redacted());
            assertFalse(cloudBody.get().contains("203.0.113.45"), "the cloud never saw the IP");
            assertFalse(cloudBody.get().contains("root"), "nor the user name");

            int calls = s.requests.get();
            ExplanationService.Explanation again = svc.explain(ExplanationService.AUTO, saved);
            assertTrue(again.cached());
            assertEquals(calls, s.requests.get(), "a cache hit makes no call");

            cloudStatus.put("s", 500);
            ExplanationService.Explanation fallback = svc.explain(ExplanationService.AUTO, finding);
            assertEquals("local", fallback.provider(), "cloud failed: the local model answered");
            assertEquals("Local answer", fallback.text());
        }
    }

    @Test
    void offlineMeansInstantTemplatesN20() {
        ExplanationService svc = new ExplanationService();
        svc.register(new ClaudeProvider("k", "m", "http://127.0.0.1:1/v1/messages", "v", client, RetryPolicy.standard()));
        svc.register(new OpenAiCompatibleProvider("http://127.0.0.1:1/v1", "m", null, client, RetryPolicy.none()));
        svc.setOnline(() -> false);
        long start = System.nanoTime();
        ExplanationService.Explanation e = svc.explain(ExplanationService.AUTO, finding);
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertEquals("offline", e.provider());
        assertTrue(e.fellBack());
        assertTrue(e.text().contains("brute force"));
        assertTrue(ms < 1_000, "took " + ms + " ms: cloud was skipped, not retried");
        assertNotNull(e.error());
    }

    @Test
    void explicitChoiceReportsWhyItFellBack() {
        ExplanationService svc = new ExplanationService();
        svc.register(new GeminiProvider("", "m", "http://127.0.0.1:1", client, FAST));
        ExplanationService.Explanation e = svc.explain("gemini", finding);
        assertEquals("offline", e.provider());
        assertEquals(Kind.NOT_CONFIGURED.userMessage(), e.error());
        assertEquals(List.of("gemini", "offline"), svc.providerNames());
    }

    private ClaudeProvider claude(FakeServer s) {
        return new ClaudeProvider("k", "m", s.base() + "/v1/messages", "v", client, FAST);
    }

    private static Finding copyWithId(Finding f, long id) {
        Finding c = new Finding(f.source(), f.target(), f.ruleId(), f.score(), f.description(), f.evidence(), f.timestamp());
        c.setId(id);
        return c;
    }

    @FunctionalInterface
    private interface Call {
        void run() throws LlmException;
    }

    private static Kind kind(Call c) {
        try {
            c.run();
            fail("expected an LlmException");
            return null;
        } catch (LlmException e) {
            return e.kind();
        }
    }

    private static final class MemoryCache implements ExplanationCache {
        private final Map<String, String> map = new HashMap<>();

        @Override
        public Optional<String> find(long findingId, String provider) {
            return Optional.ofNullable(map.get(findingId + "|" + provider));
        }

        @Override
        public void store(long findingId, String provider, String text) {
            map.put(findingId + "|" + provider, text);
        }
    }

    private static final class MutableClock extends Clock {
        Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
