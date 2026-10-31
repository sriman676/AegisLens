package com.aegislens.intrusion;

import com.aegislens.core.Finding;
import com.aegislens.core.MalformedLogException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/** Sysmon exports (wevtutil XML) and the host detectors HOST-001 to HOST-009, on sample-data/sysmon-sample.xml. */
class SysmonTest {

    private static final Path SAMPLE = Path.of("sample-data", "sysmon-sample.xml");

    @TempDir
    Path dir;

    private static HostDetectionEngine engine(Set<String> off) {
        HostNetworkDetector network = new HostNetworkDetector("203.0.113.66"::equals, "bad.example.org"::equals,
                d -> d.startsWith("paypa1.") ? Optional.of("paypal") : Optional.empty());
        return new HostDetectionEngine(network, rule -> !off.contains(rule));
    }

    private static List<Finding> run(HostDetectionEngine engine, List<SysmonEvent> events) {
        return events.stream().flatMap(e -> engine.process(e).stream()).toList();
    }

    @Test
    void sampleKeepsOnlySupportedSysmonEventsOldestFirst() throws Exception {
        List<SysmonEvent> events = new SysmonXmlSource().parse(SAMPLE);
        assertEquals(14, events.size(), "event 5 and the Security event 4624 are skipped");
        for (int i = 1; i < events.size(); i++) {
            assertFalse(events.get(i).timestamp().isBefore(events.get(i - 1).timestamp()), "sorted oldest first");
        }
        assertEquals("LAB-PC-01", events.get(0).computer());
        assertEquals("notepad.exe", SysmonEvent.fileName(events.get(0).get("Image")));
    }

    @Test
    void everyHostRuleFiresOnceOnTheSampleAndOrdinaryEventsStayQuiet() throws Exception {
        List<SysmonEvent> events = new SysmonXmlSource().parse(SAMPLE);
        List<Finding> found = run(engine(Set.of()), events);
        Map<String, Long> perRule = found.stream().collect(Collectors.groupingBy(Finding::ruleId, Collectors.counting()));
        for (int i = 1; i <= 9; i++) {
            assertEquals(1L, perRule.get("HOST-00" + i), "HOST-00" + i + " in " + perRule);
        }
        assertTrue(run(engine(Set.of()), events.subList(0, 5)).isEmpty(), "notepad, a DNS lookup, chrome, a script, a service setting");
        Finding ps = found.stream().filter(f -> f.ruleId().equals("HOST-001")).findFirst().orElseThrow();
        assertEquals(80, ps.score(), "encoded command + hidden window = 70 + 10");
        assertEquals("encoded command, hidden window", ps.evidence().get("signs"));
        assertEquals("sysmon", ps.source());
        assertEquals(80, found.stream().filter(f -> f.ruleId().equals("HOST-009")).findFirst().orElseThrow().score(),
                "a service program in C:\\Users\\Public scores 60 + 20");
        assertTrue(found.stream().filter(f -> f.ruleId().equals("HOST-009")).findFirst().orElseThrow().target()
                .endsWith("\\Services\\UpdaterSvc"), "the service, not the ImagePath value");
        assertEquals("203.0.113.66", found.stream().filter(f -> f.ruleId().equals("HOST-005")).findFirst().orElseThrow().target());
    }

    @Test
    void rulesSwitchedOffInSettingsAreDropped() throws Exception {
        List<Finding> found = run(engine(Set.of("HOST-003", "HOST-006")), new SysmonXmlSource().parse(SAMPLE));
        assertTrue(found.stream().noneMatch(f -> f.ruleId().equals("HOST-003") || f.ruleId().equals("HOST-006")));
        assertEquals(7, found.size());
    }

    @Test
    void nearMissesAreNotReported() {
        HostDetectionEngine engine = engine(Set.of());
        assertTrue(engine.process(start("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\report.ps1", "C:\\Windows\\explorer.exe")).isEmpty(),
                "one sign that is not an encoded command is normal admin work");
        assertTrue(engine.process(start("C:\\Windows\\System32\\certutil.exe", "certutil.exe -hashfile setup.exe SHA256",
                "C:\\Windows\\System32\\cmd.exe")).isEmpty(), "certutil checking a hash is fine");
        assertTrue(engine.process(start("C:\\Windows\\splwow64.exe", "splwow64.exe 8192",
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")).isEmpty(), "Word printing is fine");
        assertTrue(engine.process(event(SysmonEvent.REGISTRY_VALUE, Map.of("TargetObject",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\x", "Details", "a"))).isEmpty());
        assertTrue(engine.process(event(SysmonEvent.DNS_QUERY, Map.of("QueryName", "www.example.com."))).isEmpty());
        assertFalse(engine.process(event(SysmonEvent.DNS_QUERY, Map.of("QueryName", "bad.example.org."))).isEmpty(),
                "a listed domain is found even with DNS's trailing dot");
    }

    @Test
    void falseAlarmsSeenOnRealSysmonDataStayQuiet() throws Exception {
        String chrome = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
        HostDetectionEngine engine = engine(Set.of());
        assertTrue(engine.process(start("C:\\WINDOWS\\system32\\cmd.exe", "C:\\WINDOWS\\system32\\cmd.exe /d /s /c "
                + "\"\"C:\\Users\\me\\.ext\\native-host.bat\" chrome-extension://fcoeoabgfenejglbffodgkkbkcdhcgfn/ "
                + "--parent-window=0\"", chrome)).isEmpty(), "a browser extension's native-messaging helper is normal");
        assertEquals(60, engine.process(start("C:\\WINDOWS\\system32\\cmd.exe", "cmd.exe /c whoami", chrome)).get(0).score(),
                "a browser starting a shell for any other reason is still reported");
        HostNetworkDetector realLookalikes = new HostNetworkDetector(ip -> false, d -> false,
                com.aegislens.web.LookalikeChecker.bundled()::imitates);
        assertTrue(realLookalikes.detect(event(SysmonEvent.DNS_QUERY, Map.of("QueryName", "those.srmap.univ"))).isEmpty(),
                "a campus or company internal DNS name is not a look-alike");
    }

    @Test
    void utf16ExportFromPowerShellIsRead() throws Exception {
        byte[] text = Files.readString(SAMPLE).getBytes(StandardCharsets.UTF_16LE);
        byte[] withBom = new byte[text.length + 2];
        withBom[0] = (byte) 0xFF;
        withBom[1] = (byte) 0xFE;
        System.arraycopy(text, 0, withBom, 2, text.length);
        assertEquals(14, new SysmonXmlSource().parse(Files.write(dir.resolve("sysmon-utf16.xml"), withBom)).size());
    }

    @Test
    void externalEntitiesAreRefused() throws Exception {
        Path evil = Files.writeString(dir.resolve("evil.xml"), "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>"
                + "<Event><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>"
                + "<TimeCreated SystemTime='2026-10-31T09:00:00Z'/></System><EventData><Data Name='Image'>&e;</Data></EventData></Event>");
        assertThrows(MalformedLogException.class, () -> new SysmonXmlSource().parse(evil));
    }

    private static SysmonEvent start(String image, String command, String parent) {
        return event(SysmonEvent.PROCESS_CREATE, Map.of("Image", image, "CommandLine", command, "ParentImage", parent));
    }

    private static SysmonEvent event(int id, Map<String, String> fields) {
        return new SysmonEvent(Instant.parse("2026-10-31T09:00:00Z"), id, "LAB-PC-01", new HashMap<>(fields), "test");
    }
}
