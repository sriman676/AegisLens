package com.aegislens.net;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/** RetryPolicy, BoundedBody, certificate pinning, ConnectivityMonitor, NetworkSettings on local fake servers. */
class NetTest {

    private final List<Duration> waits = new ArrayList<>();
    private final RetryPolicy retry = new RetryPolicy(3, Duration.ofMillis(100), waits::add, new Random(1));
    private final HttpClient client = HttpClient.newHttpClient();

    @Test
    void retries429ThenSucceedsAndHonoursRetryAfter() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        try (FakeServer s = FakeServer.http(Map.of("/x", ex -> {
            if (calls.incrementAndGet() == 1) {
                ex.getResponseHeaders().add("Retry-After", "7");
                FakeServer.reply(ex, 429, "{}");
            } else {
                FakeServer.reply(ex, 200, "{\"ok\":true}");
            }
        }))) {
            HttpResponse<String> r = retry.execute(() -> get(s.base() + "/x"));
            assertEquals(200, r.statusCode());
            assertEquals(List.of(Duration.ofSeconds(7)), waits, "waited what Retry-After asked");
        }
    }

    @Test
    void serverErrorsAreRetriedThenReturnedAndClientErrorsNever() throws Exception {
        try (FakeServer s = FakeServer.http(Map.of("/500", ex -> FakeServer.reply(ex, 500, "{}"),
                "/400", ex -> FakeServer.reply(ex, 400, "{}")))) {
            assertEquals(500, retry.execute(() -> get(s.base() + "/500")).statusCode());
            assertEquals(2, waits.size(), "3 attempts = 2 waits");
            assertTrue(waits.get(1).compareTo(waits.get(0)) > 0, "exponential backoff");
            waits.clear();
            assertEquals(400, retry.execute(() -> get(s.base() + "/400")).statusCode());
            assertTrue(waits.isEmpty(), "a 400 is never retried");
        }
    }

    @Test
    void networkErrorsAreRetriedThenThrown() {
        assertThrows(IOException.class, () -> retry.execute(() -> get("http://127.0.0.1:1/unreachable")));
        assertEquals(2, waits.size());
    }

    @Test
    void oversizedResponsesAreCutOff() throws Exception {
        String big = "x".repeat(2 * 1024 * 1024);
        try (FakeServer s = FakeServer.http(Map.of("/big", ex -> FakeServer.reply(ex, 200, big)))) {
            HttpRequest req = HttpRequest.newBuilder(URI.create(s.base() + "/big")).build();
            HttpResponse<String> declared = client.send(req, BoundedBody.ofString(BoundedBody.LLM_LIMIT));
            assertThrows(ResponseTooLargeException.class, () -> BoundedBody.requireBody(declared, BoundedBody.LLM_LIMIT));
            HttpResponse<String> ok = client.send(req, BoundedBody.ofString(3L * 1024 * 1024));
            assertEquals(big.length(), ok.body().length());
        }
    }

    @Test
    void pinnedClientTrustsOnlyTheMatchingCertificate() throws Exception {
        try (FakeServer s = FakeServer.https(Map.of("/api/v1/health", ex -> FakeServer.reply(ex, 200, "{\"ok\":true}")));
             HttpClientFactory factory = HttpClientFactory.defaults()) {
            HttpRequest req = HttpRequest.newBuilder(URI.create(s.base() + "/api/v1/health")).build();
            HttpClient good = factory.pinnedClient(FakeServer.certificatePin());
            assertEquals(200, good.send(req, HttpResponse.BodyHandlers.ofString()).statusCode());

            HttpClient wrong = factory.pinnedClient("00".repeat(32));
            assertThrows(IOException.class, () -> wrong.send(req, HttpResponse.BodyHandlers.ofString()));
            assertThrows(IOException.class, () -> factory.client().send(req, HttpResponse.BodyHandlers.ofString()),
                    "the normal client does not trust a self-signed certificate");
            assertThrows(IllegalArgumentException.class, () -> new PinnedTrustManager("not-a-fingerprint"));
        }
    }

    @Test
    void connectivityMonitorReportsOnlineOfflineAndClockSkew() throws Exception {
        try (FakeServer s = FakeServer.http(Map.of("/", ex -> {
            FakeServer.reply(ex, 404, "");
        }))) {
            List<ConnectivityMonitor.Status> heard = new ArrayList<>();
            Clock tenMinutesBehind = Clock.offset(Clock.systemUTC(), Duration.ofMinutes(-10));   // the server sends its own real Date header
            ConnectivityMonitor up = new ConnectivityMonitor(client, List.of(URI.create(s.base() + "/")), tenMinutesBehind);
            up.addListener(heard::add);
            ConnectivityMonitor.Status st = up.checkNow();
            assertTrue(st.online(), "even a 404 means the host is reachable");
            assertTrue(st.clockWarning(), "our clock is 10 minutes behind the server");
            assertEquals(1, heard.size());
            assertEquals(Thread.MIN_PRIORITY, up.getPriority());
        }
        ConnectivityMonitor down = new ConnectivityMonitor(client, List.of(URI.create("http://127.0.0.1:1/")), Clock.systemUTC());
        assertFalse(down.checkNow().online());
        assertFalse(new ConnectivityMonitor(client, List.of(), Clock.systemUTC()).checkNow().online(), "no hosts: offline");
    }

    @Test
    void proxySettings() {
        NetworkSettings none = NetworkSettings.from(k -> null);
        assertTrue(none.selector().isEmpty());
        NetworkSettings proxy = NetworkSettings.from(Map.of(NetworkSettings.PROXY_HOST, "proxy.example", NetworkSettings.PROXY_PORT, "3128")::get);
        assertTrue(proxy.selector().isPresent());
        assertEquals(3128, proxy.proxyPort());
        assertTrue(NetworkSettings.from(Map.of(NetworkSettings.PROXY_PORT, "nope")::get).selector().isEmpty());
    }

    private HttpResponse<String> get(String url) throws IOException, InterruptedException {
        return client.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(2)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

}
