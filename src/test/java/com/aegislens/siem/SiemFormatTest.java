package com.aegislens.siem;

import com.aegislens.core.Finding;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SiemFormatTest {

    private static final Instant T = Instant.parse("2026-11-10T08:30:00.123Z");

    private static Finding finding(String target, int score, String description, Map<String, String> evidence) {
        Finding f = new Finding("intrusion", target, "NET-001", score, description, evidence, T);
        f.setId(42);
        return f;
    }

    @Test
    void cefHasHeaderSeverityAndSourceAddress() {
        String cef = SiemFormat.cef(finding("203.0.113.45", 72, "5 failed SSH logins", Map.of("count", "5")), "1.0.0");
        assertTrue(cef.startsWith("CEF:0|AegisLens|AegisLens|1.0.0|NET-001|5 failed SSH logins|7|rt=1794299400123 src=203.0.113.45 "), cef);
        assertTrue(cef.contains(" cat=HIGH "));
        assertTrue(cef.contains(" cn1Label=score cn1=72 "));
        assertTrue(cef.contains(" cs4Label=evidence cs4=count: 5"));
        assertTrue(cef.endsWith(" externalId=42"));
    }

    @Test
    void cefEscapesPipesBackslashesEqualsAndNewLines() {
        Map<String, String> evidence = new LinkedHashMap<>();
        evidence.put("cmd", "a=b\\c\r\nnext");
        String cef = SiemFormat.cef(finding("C:\\Users\\x|y", 50, "pipe | and \\ here", evidence), "1.0.0");
        assertTrue(cef.contains("|pipe \\| and \\\\ here|5|"), cef);
        assertTrue(cef.contains("cs2=C:\\\\Users\\\\x|y"), "| needs no escape in extensions: " + cef);
        assertTrue(cef.contains("cs4=cmd: a\\=b\\\\c  next"), cef);
        assertFalse(cef.contains("\n") || cef.contains("\r"));
        assertFalse(cef.contains(" src="), "a path is not an address");
    }

    @Test
    void rawLogLinesAreNeverSent() {
        Finding f = finding("203.0.113.45", 40, "x", Map.of("line", "Failed password for root", "count", "3"));
        assertFalse(SiemFormat.cef(f, "1").contains("Failed password"));
        assertFalse(SiemFormat.json(f, "1", "pc").contains("Failed password"));
    }

    @Test
    void jsonUsesElasticCommonSchemaNames() throws Exception {
        JsonNode j = new ObjectMapper().readTree(SiemFormat.json(finding("2001:db8::7", 90, "sqlmap", Map.of("ua", "sqlmap/1.7")), "1.0.0", "host1"));
        assertEquals("2026-11-10T08:30:00.123Z", j.path("@timestamp").asText());
        assertEquals("alert", j.path("event").path("kind").asText());
        assertEquals(90, j.path("event").path("risk_score").asInt());
        assertEquals("NET-001", j.path("rule").path("id").asText());
        assertEquals("2001:db8::7", j.path("source").path("ip").asText());
        assertEquals("CRITICAL", j.path("aegislens").path("severity").asText());
        assertEquals("sqlmap/1.7", j.path("aegislens").path("evidence").path("ua").asText());
        assertEquals("host1", j.path("observer").path("hostname").asText());
    }

    @Test
    void syslogHeaderFollowsRfc5424() {
        Finding f = finding("203.0.113.45", 90, "x", null);
        assertEquals("<82>1 2026-11-10T08:30:00.123Z mypc aegislens - FINDING - CEF:0|x", SiemFormat.syslog(f, "My PC", "CEF:0|x", T));
        assertEquals("<85>1 2026-11-10T08:30:00.123Z - aegislens - FINDING - p", SiemFormat.syslog(finding("a", 10, "x", null), " ", "p", T));
    }

    @Test
    void severitiesAndAddresses() {
        assertEquals(0, SiemFormat.cefSeverity(0));
        assertEquals(10, SiemFormat.cefSeverity(100));
        assertEquals(3, SiemFormat.syslogSeverity(60));
        assertTrue(SiemFormat.isIp("10.0.0.1"));
        assertTrue(SiemFormat.isIp("::1"));
        assertFalse(SiemFormat.isIp("999.1.1.1"));
        assertFalse(SiemFormat.isIp("evil.example"));
        assertFalse(SiemFormat.isIp("HKLM\\Software\\Run"));
    }
}
