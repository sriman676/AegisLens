package com.aegislens.web;

import com.aegislens.core.AnalysisException;
import com.aegislens.core.Finding;
import com.aegislens.intrusion.Thresholds;
import com.aegislens.net.FakeServer;
import com.aegislens.util.InjectionPatterns;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** R9: W1-W6 on sample-data/urls.txt, lookalikes, HTML checks and the SSRF guard. */
class WebTest {

    private static UrlAnalyzer urls;
    private static List<String> samples;

    @BeforeAll
    static void setUp() throws Exception {
        urls = new UrlAnalyzer(LookalikeChecker.bundled(), new InjectionPatterns(Thresholds.DEFAULT_INJECTION),
                v -> v.equals("known-bad.example.test"));
        samples = Files.readAllLines(Path.of("sample-data", "urls.txt"));
    }

    @Test
    void w1WellKnownSitesAreClean() throws Exception {
        for (String u : samples.subList(0, 3)) {
            assertEquals(List.of(), urls.analyze(u), u);
        }
    }

    @Test
    void w2LookalikesScoreAtLeast75() throws Exception {
        for (String u : samples.subList(3, 5)) {
            Finding f = only(u, UrlAnalyzer.PHISHING);
            assertTrue(f.score() >= 75, u + " scored " + f.score());
            assertTrue(f.evidence().get("lookalike").startsWith("imitates "), u);
        }
    }

    @Test
    void w3RawIpOverHttpScores55() throws Exception {
        assertEquals(55, only(samples.get(5), UrlAnalyzer.PHISHING).score());
    }

    @Test
    void w4InjectionInTheQueryScores70() throws Exception {
        for (String u : samples.subList(6, 8)) {
            assertEquals(70, only(u, UrlAnalyzer.INJECTION).score(), u);
        }
    }

    @Test
    void w5AtSignAndPunycodeGiveAtLeastTwoIndicators() throws Exception {
        Finding f = only(samples.get(8), UrlAnalyzer.PHISHING);
        assertTrue(f.score() >= 55, f.evidence().toString());
        Finding at = only("https://www.paypal.com@203.0.113.9/login", UrlAnalyzer.PHISHING);
        assertTrue(at.evidence().containsKey("at-sign") && at.evidence().containsKey("raw-ip"), at.evidence().toString());
    }

    @Test
    void lookalikeRules() throws Exception {
        LookalikeChecker c = LookalikeChecker.bundled();
        assertEquals("paypal.com", c.imitates("xn--pypal-4ve.com").orElseThrow(), "Cyrillic a, as punycode");
        assertEquals("microsoft.com", c.imitates("rnicrosoft-support.test").orElseThrow(), "rn read as m");
        assertEquals("amazon.com", c.imitates("arnazom.test").orElseThrow(), "edit distance");
        assertTrue(c.imitates("mail.google.com").isEmpty(), "the real brand's subdomain");
        assertTrue(c.imitates("email.example.test").isEmpty(), "short brands only match exactly");
        assertEquals(1, LookalikeChecker.distance("paypal", "paypa1"));
    }

    @Test
    void threatListsAndBadInput() throws Exception {
        assertEquals(90, only("https://known-bad.example.test/x", UrlAnalyzer.THREAT_LIST).score());
        assertThrows(AnalysisException.class, () -> urls.analyze("javascript:alert(1)"));
        assertThrows(AnalysisException.class, () -> urls.analyze(" "));
        assertThrows(AnalysisException.class, () -> urls.analyze("https://" + "a".repeat(5000)));
        assertEquals(List.of(), urls.analyze("http://plain-old-site.example.test/"), "plain http alone is not reported");
    }

    @Test
    void htmlChecks() throws Exception {
        HtmlAnalyzer html = new HtmlAnalyzer();
        URI page = URI.create("http://shop.example.test/login");
        String bad = "<form action='https://collect.evil.test/p'><input type=\"password\" name=p></form>"
                + "<iframe src=\"https://x.test\" width=\"0\" height=\"0\"></iframe>"
                + "<meta http-equiv=\"refresh\" content=\"0; url=https://elsewhere.test/\">"
                + "<script>eval(atob('YWxlcnQoMSk='))</script>";
        Finding f = html.analyze(bad, page).get(0);
        assertEquals(HtmlAnalyzer.MAX, f.score(), f.evidence().toString());
        assertEquals(5, f.evidence().size());
        assertEquals(List.of(), html.analyze("<form action=\"/search\"><input type=text></form>", URI.create("https://ok.test/")));
        assertEquals(List.of(), html.analyze("<input type=password>", URI.create("https://ok.test/")), "https is fine");
        assertTrue(html.analyze("<iframe hidden src=x></iframe>").get(0).evidence().containsKey("hidden-iframe"));
        assertEquals(List.of(), html.analyze("<" + "a".repeat(100_000)), "a broken page is just text");
    }

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "::1", "fd00::1"})
    void w6PrivateAndLocalAddressesAreRefused(String ip) throws Exception {
        HeaderChecker checker = new HeaderChecker(host -> new InetAddress[] {InetAddress.getByName(ip)},
                a -> com.aegislens.util.IpRules.whyNotBlockable(a.getHostAddress()).isEmpty());
        AnalysisException e = assertThrows(AnalysisException.class, () -> checker.fetch("http://intranet.example.test/"));
        assertTrue(e.getMessage().contains("SSRF guard"), e.getMessage());
    }

    @Test
    void theRealGuardRefusesLocalhostAndOtherSchemes() {
        HeaderChecker real = new HeaderChecker();
        assertThrows(AnalysisException.class, () -> real.fetch("http://127.0.0.1:1/"));
        assertThrows(AnalysisException.class, () -> real.fetch("http://localhost/"));
        assertThrows(AnalysisException.class, () -> real.fetch("file:///etc/passwd"));
        assertThrows(AnalysisException.class, () -> real.fetch("ftp://x.example.test/"));
    }

    @Test
    void redirectsAreCheckedAgainAndHeadersReported() throws Exception {
        try (FakeServer s = FakeServer.http(Map.of(
                "/start", ex -> {
                    ex.getResponseHeaders().add("Location", "/page");
                    FakeServer.reply(ex, 302, "");
                },
                "/page", ex -> {
                    ex.getResponseHeaders().add("X-Frame-Options", "DENY");
                    FakeServer.reply(ex, 200, "<input type=password>");
                },
                "/to-metadata", ex -> {
                    ex.getResponseHeaders().add("Location", "http://169.254.169.254/latest/meta-data/");
                    FakeServer.reply(ex, 302, "");
                },
                "/loop", ex -> {
                    ex.getResponseHeaders().add("Location", "/loop");
                    FakeServer.reply(ex, 302, "");
                }))) {
            Set<String> loopbackOnly = Set.of("127.0.0.1");
            HeaderChecker checker = new HeaderChecker(InetAddress::getAllByName, a -> loopbackOnly.contains(a.getHostAddress()));
            HeaderChecker.Result r = checker.fetch(s.base() + "/start");
            assertEquals(2, r.chain().size(), "one redirect followed");
            assertEquals(List.of("content-security-policy", "x-content-type-options"), r.missing(), "HSTS is not expected on http");
            assertEquals(25, HeaderChecker.headerFinding(r).orElseThrow().score());
            assertTrue(new HtmlAnalyzer().analyze(r.html(), r.finalUrl()).get(0).evidence().containsKey("password-http"));

            AnalysisException e = assertThrows(AnalysisException.class, () -> checker.fetch(s.base() + "/to-metadata"));
            assertTrue(e.getMessage().contains("169.254.169.254"), "a redirect into the cloud metadata address is refused");
            assertTrue(assertThrows(AnalysisException.class, () -> checker.fetch(s.base() + "/loop")).getMessage().contains("redirects"));
        }
    }

    @Test
    void theConnectionGoesToTheCheckedAddressWithoutASecondLookup() throws Exception {
        try (FakeServer s = FakeServer.http(Map.of("/", ex -> FakeServer.reply(ex, 200, "<p>ok</p>")))) {
            int port = URI.create(s.base()).getPort();
            java.util.concurrent.atomic.AtomicInteger lookups = new java.util.concurrent.atomic.AtomicInteger();
            HeaderChecker checker = new HeaderChecker(host -> {
                lookups.incrementAndGet();
                return new InetAddress[] {InetAddress.getByName("127.0.0.1")};
            }, a -> a.isLoopbackAddress());
            HeaderChecker.Result r = checker.fetch("http://rebind.example.test:" + port + "/");
            assertEquals(200, r.status(), "rebind.example.test does not exist in DNS: only the checked address was used");
            assertEquals(1, lookups.get(), "the name is resolved once per hop");
        }
    }

    @Test
    void certificatesAreStillCheckedOnThePinnedConnection() throws Exception {
        try (FakeServer s = FakeServer.https(Map.of("/", ex -> FakeServer.reply(ex, 200, "secret")))) {
            int port = URI.create(s.base()).getPort();
            HeaderChecker checker = new HeaderChecker(host -> new InetAddress[] {InetAddress.getByName("127.0.0.1")},
                    a -> a.isLoopbackAddress());
            AnalysisException e = assertThrows(AnalysisException.class, () -> checker.fetch("https://localhost:" + port + "/"));
            assertTrue(e.getMessage().startsWith("Could not fetch"), "a self-signed certificate is refused: " + e.getMessage());
        }
    }

    private static Finding only(String url, String rule) throws AnalysisException {
        List<Finding> found = urls.analyze(url).stream().filter(f -> f.ruleId().equals(rule)).toList();
        assertEquals(1, found.size(), url + " -> " + urls.analyze(url));
        return found.get(0);
    }
}
