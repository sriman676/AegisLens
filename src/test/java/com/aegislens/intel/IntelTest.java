package com.aegislens.intel;

import com.aegislens.core.Finding;
import com.aegislens.db.Database;
import com.aegislens.db.FeedStateRepository;
import com.aegislens.db.IocRepository;
import com.aegislens.db.VtCacheRepository;
import com.aegislens.db.VtResult;
import com.aegislens.intrusion.TokenBucket;
import com.aegislens.net.FakeServer;
import com.aegislens.net.RetryPolicy;
import com.aegislens.util.CidrSet;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/** R7: feed catalog, parsers, updater lifecycle, CIDR edge cases and VirusTotal, all on local fake servers. */
class IntelTest {

    static final String SPAMHAUS = "{\"cidr\":\"203.0.113.0/24\",\"sblid\":\"SBL1\",\"rir\":\"apnic\"}\n"
            + "{\"cidr\":\"198.51.100.0/25\",\"sblid\":\"SBL2\"}\n"
            + "{\"cidr\":\"not-a-cidr\"}\n"
            + "{\"type\":\"metadata\",\"timestamp\":1730000000,\"size\":2,\"records\":2,\"copyright\":\"(c) Spamhaus\"}\n";
    private final HttpClient client = HttpClient.newHttpClient();
    private final RetryPolicy fast = new RetryPolicy(2, Duration.ZERO, d -> { }, new Random(1));

    @Test
    void parsersForEveryFormat() {
        assertEquals(Set.of("203.0.113.0/24", "198.51.100.0/25"), FeedParsers.parse(feed("ndjson-cidr", "CIDR"), SPAMHAUS),
                "metadata line and invalid CIDR skipped");
        String drop = "; Spamhaus DROP List 2026/10/30\n; Last-Modified: x\n192.0.2.0/24 ; SBL123\n10.0.0.0/33 ; bad\n; EOF\n";
        assertEquals(Set.of("192.0.2.0/24"), FeedParsers.parse(feed("cidr-lines", "CIDR"), drop));
        String feodo = "# Feodo Tracker\n#\n203.0.113.77\n2001:db8::7\n999.1.1.1\nhello\n\n";
        assertEquals(Set.of("203.0.113.77", "2001:db8::7"), FeedParsers.parse(feed("ip-lines", "IP"), feodo));
        String hashes = "# sha256\n" + "A".repeat(64) + "\n" + "b".repeat(63) + "\n" + "md5-not-wanted-d41d8cd98f00b204e9800998ecf8427e\n";
        assertEquals(Set.of("a".repeat(64)), FeedParsers.parse(feed("hash-lines", "HASH"), hashes), "upper case normalised, short hash dropped");
        FeedDefinition json = new FeedDefinition("j", URI.create("https://x"), "json-field", "IP", true, Duration.ofHours(24),
                Duration.ofMinutes(15), null, null, false, false, "ip_address", "a");
        assertEquals(Set.of("192.0.2.9"), FeedParsers.parse(json, "[{\"ip_address\":\"192.0.2.9\"},{\"ip_address\":\"x\"},{}]"));
        assertTrue(FeedParsers.parse(json, "<html>maintenance</html>").isEmpty());
    }

    @Test
    void catalogDefaultsAndValidation() throws Exception {
        List<FeedDefinition> defaults = FeedCatalog.load(null);
        assertEquals(List.of("feodo-c2", "spamhaus-drop"), defaults.stream().map(FeedDefinition::name).toList());
        FeedDefinition feodo = defaults.get(0);
        assertTrue(feodo.enabled() && feodo.allowEmpty() && feodo.c2());
        assertEquals("Auth-Key", feodo.headerName());
        assertTrue(defaults.get(1).attribution().contains("Spamhaus"));
        Properties p = new Properties();
        p.setProperty("feed.plain.url", "http://feeds.example/list.txt");
        p.setProperty("feed.plain.format", "ip-lines");
        p.setProperty("feed.plain.kind", "IP");
        p.setProperty("feed.weird.url", "https://feeds.example/x");
        p.setProperty("feed.weird.format", "yaml");
        p.setProperty("feed.weird.kind", "IP");
        assertTrue(FeedCatalog.parse(p).isEmpty(), "http without allow.http and unknown formats are skipped");
    }

    @Test
    void feedLifecycle() throws Exception {
        AtomicReference<String> body = new AtomicReference<>(SPAMHAUS);
        AtomicReference<String> seenEtag = new AtomicReference<>();
        AtomicReference<String> seenAuth = new AtomicReference<>();
        try (FakeServer s = FakeServer.http(Map.of("/drop", ex -> {
            seenEtag.set(ex.getRequestHeaders().getFirst("If-None-Match"));
            seenAuth.set(ex.getRequestHeaders().getFirst("Auth-Key"));
            if ("\"v1\"".equals(seenEtag.get()) && body.get().equals(SPAMHAUS)) {
                FakeServer.reply(ex, 304, "");
                return;
            }
            ex.getResponseHeaders().add("ETag", "\"v1\"");
            FakeServer.reply(ex, 200, body.get());
        }, "/empty", ex -> FakeServer.reply(ex, 200, "# no active C2 right now\n")));
             Database db = Database.inMemory()) {
            MutableClock clock = new MutableClock(Instant.parse("2026-10-30T06:00:00Z"));
            IocRepository iocs = new IocRepository(db);
            FeedStateRepository states = new FeedStateRepository(db);
            FeedDefinition drop = new FeedDefinition("spamhaus-drop", URI.create(s.base() + "/drop"), "ndjson-cidr", "CIDR", true,
                    Duration.ofHours(24), Duration.ofMinutes(60), "Auth-Key", "TEST_FEED_KEY", false, false, null, "Spamhaus");
            FeedDefinition feodo = new FeedDefinition("feodo-c2", URI.create(s.base() + "/empty"), "ip-lines", "IP", true,
                    Duration.ofHours(24), Duration.ofMinutes(15), null, null, true, true, null, "abuse.ch");
            FeedDefinition off = new FeedDefinition("disabled", URI.create(s.base() + "/never"), "ip-lines", "IP", false,
                    Duration.ofHours(24), Duration.ofMinutes(15), null, null, false, false, null, "x");
            FeedUpdater u = new FeedUpdater(List.of(drop, feodo, off), client, fast, iocs, states,
                    Map.of("TEST_FEED_KEY", "secret-123")::get, clock);

            List<FeedUpdater.Result> first = u.updateDue();
            assertEquals(FeedUpdater.Outcome.UPDATED, first.get(0).outcome());
            assertEquals(2, first.get(0).entries());
            assertEquals("secret-123", seenAuth.get(), "auth header value from the environment");
            assertEquals(FeedUpdater.Outcome.UPDATED, first.get(1).outcome(), "an empty Feodo list is normal");
            assertEquals(2, first.size(), "the disabled feed is never fetched");
            CidrSet[] intel = threatIntel(iocs);
            assertTrue(intel[0].contains("203.0.113.200"), "the new list is usable for detection");

            assertTrue(u.updateDue().isEmpty(), "not due again within 24 h");
            clock.now = clock.now.plus(Duration.ofHours(25));
            assertEquals(FeedUpdater.Outcome.NOT_MODIFIED, u.updateDue().get(0).outcome());
            assertEquals("\"v1\"", seenEtag.get(), "conditional GET with the stored ETag");

            clock.now = clock.now.plus(Duration.ofHours(25));
            body.set("<html>we changed the format</html>");
            FeedUpdater.Result broken = u.updateDue().get(0);
            assertEquals(FeedUpdater.Outcome.FAILED, broken.outcome());
            assertTrue(broken.message().contains("zero entries"));
            assertEquals(2, iocs.countByKind().get("CIDR"), "old data kept");

            clock.now = clock.now.plus(Duration.ofHours(25));
            body.set("x".repeat(21 * 1024 * 1024));
            assertTrue(u.updateDue().get(0).message().contains("20 MB"));
            assertEquals(2, iocs.countByKind().get("CIDR"));

            assertEquals(FeedUpdater.Outcome.SKIPPED, u.updateAllNow().get(0).outcome(), "minimum interval respected");
            clock.now = clock.now.plus(Duration.ofDays(4));
            FeedUpdater.Status st = u.status().stream().filter(x -> x.feed().equals("spamhaus-drop")).findFirst().orElseThrow();
            assertTrue(st.stale(), "no success for more than 3 days");
            assertNotNull(st.lastError());
        }
    }

    @Test
    void unreachableFeedKeepsWorkingOffline() throws Exception {
        try (Database db = Database.inMemory()) {
            IocRepository iocs = new IocRepository(db);
            iocs.addAll("CIDR", List.of("192.0.2.0/24"), "spamhaus-drop");
            FeedDefinition drop = new FeedDefinition("spamhaus-drop", URI.create("http://127.0.0.1:1/drop"), "ndjson-cidr", "CIDR",
                    true, Duration.ofHours(24), Duration.ofMinutes(60), null, null, false, false, null, "Spamhaus");
            FeedUpdater u = new FeedUpdater(List.of(drop), client, fast, iocs, new FeedStateRepository(db), k -> null, Clock.systemUTC());
            FeedUpdater.Result r = u.updateDue().get(0);
            assertEquals(FeedUpdater.Outcome.FAILED, r.outcome());
            assertTrue(r.message().contains("offline"));
            assertTrue(iocs.exists("CIDR", "192.0.2.0/24"));
        }
    }

    @Test
    void cidrEdgeCases() {
        CidrSet set = new CidrSet();
        set.add("198.51.100.7/32");
        set.add("2001:db8::/32");
        assertTrue(set.contains("198.51.100.7"));
        assertFalse(set.contains("198.51.100.8"));
        assertTrue(set.contains("::ffff:198.51.100.7"), "IPv4-mapped IPv6 is the same IPv4 address");
        assertTrue(set.contains("2001:db8:ffff::1"));
        CidrSet all = new CidrSet();
        all.add("0.0.0.0/0");
        assertTrue(all.contains("203.0.113.1"));
        assertFalse(all.contains("2001:db8::1"));
    }

    @Test
    void virusTotalLookupsCacheAndScoring() throws Exception {
        AtomicReference<String> path = new AtomicReference<>();
        AtomicReference<String> key = new AtomicReference<>();
        String known = "a".repeat(64);
        String unknown = "b".repeat(64);
        try (FakeServer s = FakeServer.http(Map.of("/api/v3/files/", ex -> {
            path.set(ex.getRequestURI().getPath());
            key.set(ex.getRequestHeaders().getFirst("x-apikey"));
            if (path.get().endsWith(known)) {
                FakeServer.reply(ex, 200, "{\"data\":{\"attributes\":{\"last_analysis_stats\":"
                        + "{\"malicious\":12,\"suspicious\":1,\"undetected\":50,\"harmless\":0,\"timeout\":1}}}}");
            } else if (path.get().endsWith(unknown)) {
                FakeServer.reply(ex, 404, "{\"error\":{\"code\":\"NotFoundError\"}}");
            } else {
                FakeServer.reply(ex, 401, "{}");
            }
        })); Database db = Database.inMemory()) {
            VtCacheRepository cache = new VtCacheRepository(db);
            VirusTotalClient vt = new VirusTotalClient("vt-key", s.base(), client, cache,
                    new TokenBucket(10, 10, System::nanoTime), 500, Clock.systemUTC());
            try {
                VtResult r = vt.lookup(known.toUpperCase()).get(10, TimeUnit.SECONDS);
                assertEquals("/api/v3/files/" + known, path.get(), "only the hash is sent");
                assertEquals("vt-key", key.get());
                assertEquals(12, r.malicious());
                assertEquals(64, r.total());
                Finding f = VirusTotalClient.finding(r, "invoice.exe", 1).orElseThrow();
                assertEquals("MAL-005", f.ruleId());
                assertEquals(90, f.score());

                VtResult u = vt.lookup(unknown).get(10, TimeUnit.SECONDS);
                assertFalse(u.known());
                assertTrue(VirusTotalClient.finding(u, "x", 1).isEmpty(), "unknown hash scores nothing");
                int calls = s.requests.get();
                vt.lookup(unknown).get(10, TimeUnit.SECONDS);
                assertEquals(calls, s.requests.get(), "404 answer cached: no second call");

                ExecutionException e = assertThrows(ExecutionException.class, () -> vt.lookup("c".repeat(64)).get(10, TimeUnit.SECONDS));
                assertEquals(VirusTotalClient.VtException.Kind.AUTH, ((VirusTotalClient.VtException) e.getCause()).kind());
            } finally {
                vt.close();
            }
            assertEquals(70, VirusTotalClient.finding(new VtResult("x", true, 5, 0, 70, Instant.now()), "t", 1).orElseThrow().score());
            assertEquals(50, VirusTotalClient.finding(new VtResult("x", true, 2, 0, 70, Instant.now()), "t", 1).orElseThrow().score());
            assertTrue(VirusTotalClient.finding(new VtResult("x", true, 2, 0, 70, Instant.now()), "t", 3).isEmpty(), "rule threshold");
        }
    }

    @Test
    void rateLimitAndDailyCapAndNoKey() throws Exception {
        AtomicLong nanos = new AtomicLong(0);
        try (FakeServer s = FakeServer.http(Map.of("/api/v3/files/", ex -> FakeServer.reply(ex, 404, "{}")));
             Database db = Database.inMemory()) {
            VirusTotalClient vt = new VirusTotalClient("k", s.base(), client, new VtCacheRepository(db),
                    new TokenBucket(4, 4 / 60.0, nanos::get), 6, Clock.systemUTC());
            try {
                List<CompletableFuture<VtResult>> jobs = new java.util.ArrayList<>();
                for (int i = 0; i < 7; i++) {
                    jobs.add(vt.lookup(String.format("%064x", i + 1)));
                }
                for (int i = 0; i < 4; i++) {
                    jobs.get(i).get(10, TimeUnit.SECONDS);
                }
                Thread.sleep(500);
                assertEquals(4, s.requests.get(), "the 5th lookup waits for the per-minute limit");
                assertFalse(jobs.get(4).isDone());
                nanos.addAndGet(Duration.ofSeconds(60).toNanos());     // a minute passes
                jobs.get(4).get(10, TimeUnit.SECONDS);
                jobs.get(5).get(10, TimeUnit.SECONDS);
                ExecutionException e = assertThrows(ExecutionException.class, () -> jobs.get(6).get(10, TimeUnit.SECONDS));
                assertEquals(VirusTotalClient.VtException.Kind.QUOTA, ((VirusTotalClient.VtException) e.getCause()).kind(), "daily cap of 6");
                assertEquals(6, s.requests.get());
            } finally {
                vt.close();
            }
            VirusTotalClient off = new VirusTotalClient("", s.base(), client, new VtCacheRepository(db),
                    new TokenBucket(4), 500, Clock.systemUTC());
            assertFalse(off.enabled());
            int before = s.requests.get();
            assertThrows(ExecutionException.class, () -> off.lookup("a".repeat(64)).get(5, TimeUnit.SECONDS));
            assertEquals(before, s.requests.get(), "no key: nothing is sent");
            off.close();
        }
    }

    private static CidrSet[] threatIntel(IocRepository iocs) throws Exception {
        CidrSet block = new CidrSet();
        for (String v : iocs.values("CIDR")) {
            block.add(v);
        }
        return new CidrSet[] {block};
    }

    private static FeedDefinition feed(String format, String kind) {
        return new FeedDefinition("t", URI.create("https://x"), format, kind, true, Duration.ofHours(24), Duration.ofMinutes(15),
                null, null, false, false, null, "test");
    }

    static final class MutableClock extends Clock {
        Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }
}
