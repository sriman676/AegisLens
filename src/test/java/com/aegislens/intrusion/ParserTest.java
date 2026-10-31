package com.aegislens.intrusion;

import com.aegislens.core.MalformedLogException;
import com.aegislens.intrusion.LogEvent.Action;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** R3 parsers against every supported format, plus hostile input. */
class ParserTest {

    static final ZoneId UTC = ZoneOffset.UTC;
    static final Clock OCT_2026 = Clock.fixed(Instant.parse("2026-10-29T12:00:00Z"), UTC);

    private final SshLogSource ssh = new SshLogSource(OCT_2026, UTC);
    private final WebLogSource web = new WebLogSource();

    @TempDir
    Path dir;

    @Test
    void sshTraditionalTimestampAndEveryMessageType() throws Exception {
        LogEvent failed = ssh.parse("Oct 21 02:14:01 srv sshd[1201]: Failed password for root from 203.0.113.45 port 51122 ssh2").orElseThrow();
        assertEquals(Action.FAILED_LOGIN, failed.action());
        assertEquals("root", failed.user());
        assertEquals("203.0.113.45", failed.ip());
        assertEquals(Instant.parse("2026-10-21T02:14:01Z"), failed.timestamp());

        LogEvent invalidFailed = ssh.parse("Oct  1 02:14:01 srv sshd[9]: Failed password for invalid user oracle from 2001:db8::7 port 22 ssh2").orElseThrow();
        assertEquals("oracle", invalidFailed.user());
        assertEquals("2001:db8::7", invalidFailed.ip());
        assertEquals("invalid user", invalidFailed.detail());

        assertEquals(Action.INVALID_USER, action("Oct 21 02:14:01 srv sshd[9]: Invalid user test from 198.51.100.4 port 4000"));
        assertEquals(Action.SUCCESS_LOGIN, action("Oct 21 02:14:01 srv sshd[9]: Accepted publickey for alice from 198.51.100.10 port 40022 ssh2: ED25519 SHA256:x"));
        assertEquals(Action.SUCCESS_LOGIN, action("Oct 21 02:14:01 srv sshd[9]: Accepted keyboard-interactive/pam for bob from 198.51.100.4 port 1 ssh2"));
        assertEquals(Action.DISCONNECT, action("Oct 21 02:14:01 srv sshd[9]: Connection closed by authenticating user root 203.0.113.45 port 51122 [preauth]"));
        assertEquals(Action.MAX_AUTH, action("Oct 21 02:14:01 srv sshd[9]: error: maximum authentication attempts exceeded for root from 203.0.113.45 port 51122 ssh2 [preauth]"));
        assertEquals(Action.DISCONNECT, action("Oct 21 02:14:01 srv sshd[9]: Disconnected from invalid user admin 203.0.113.45 port 51122 [preauth]"));
    }

    @Test
    void sshRfc3339TimestampAndOtherProgramsAreIgnored() throws Exception {
        LogEvent e = ssh.parse("2026-10-21T02:14:01.123456+05:30 host sshd[1201]: Failed password for root from 203.0.113.45 port 1 ssh2").orElseThrow();
        assertEquals(Instant.parse("2026-10-20T20:44:01.123456Z"), e.timestamp());
        assertTrue(ssh.parse("Oct 21 02:17:01 srv CRON[2001]: pam_unix(cron:session): session opened for user root").isEmpty());
        assertTrue(ssh.parse("Oct 21 02:17:01 srv sshd[2001]: pam_unix(sshd:session): session opened for user alice").isEmpty());
    }

    @Test
    void decemberLineReadInJanuaryBelongsToLastYear() throws Exception {
        SshLogSource january = new SshLogSource(Clock.fixed(Instant.parse("2027-01-02T00:30:00Z"), UTC), UTC);
        LogEvent e = january.parse("Dec 31 23:59:59 srv sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2").orElseThrow();
        assertEquals(Instant.parse("2026-12-31T23:59:59Z"), e.timestamp());
    }

    @Test
    void webCombinedFormatEdgeCases() throws Exception {
        LogEvent e = web.parse("203.0.113.45 - - [21/Oct/2026:02:20:01 +0530] \"GET /products?id=1%20OR%201=1 HTTP/1.1\" 500 120 \"-\" \"sqlmap/1.7\"").orElseThrow();
        assertEquals("GET", e.method());
        assertEquals("/products?id=1%20OR%201=1", e.path());
        assertEquals(500, e.status());
        assertEquals("sqlmap/1.7", e.userAgent());
        assertEquals(Instant.parse("2026-10-20T20:50:01Z"), e.timestamp());

        LogEvent quoted = web.parse("2001:db8::1 - bob [21/Oct/2026:09:30:01 +0000] \"GET /a\\\"b HTTP/1.1\" 404 - \"-\" \"Agent \\\"x\\\"\"").orElseThrow();
        assertEquals("/a\"b", quoted.path());
        assertEquals("bob", quoted.user());
        assertEquals("Agent \"x\"", quoted.userAgent());

        LogEvent vhost = web.parse("shop.example 198.51.100.4 - - [21/Oct/2026:09:30:01 +0000] \"GET / HTTP/2.0\" 200 10 \"-\" \"curl\"").orElseThrow();
        assertEquals("198.51.100.4", vhost.ip());

        LogEvent noRequest = web.parse("198.51.100.4 - - [21/Oct/2026:09:30:01 +0000] \"-\" 400 0 \"-\" \"-\"").orElseThrow();
        assertNull(noRequest.method());
    }

    @Test
    void forwardedForIsUsedOnlyWhenTrusted() throws Exception {
        String line = "10.0.0.2 - - [21/Oct/2026:09:30:01 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"curl\" \"203.0.113.9, 10.0.0.2\"";
        assertEquals("10.0.0.2", web.parse(line).orElseThrow().ip());
        assertEquals("203.0.113.9", new WebLogSource(true).parse(line).orElseThrow().ip());
    }

    @Test
    void syslogBothRfcsRouteByApp() throws Exception {
        SyslogParser syslog = new SyslogParser(ssh, web, OCT_2026, UTC);
        LogEvent legacy = syslog.parse("<38>Oct 21 02:14:01 srv sshd[1201]: Failed password for root from 203.0.113.45 port 1 ssh2").orElseThrow();
        assertEquals(Action.FAILED_LOGIN, legacy.action());
        assertEquals(Instant.parse("2026-10-21T02:14:01Z"), legacy.timestamp());

        LogEvent modern = syslog.parse("<38>1 2026-10-21T02:14:01Z srv sshd 1201 - - Accepted password for test from 203.0.113.45 port 2 ssh2").orElseThrow();
        assertEquals(Action.SUCCESS_LOGIN, modern.action());

        LogEvent webLine = syslog.parse("<190>1 2026-10-21T02:20:01Z web nginx - - [meta x=\"1\"] 203.0.113.45 - - [21/Oct/2026:02:20:01 +0000] \"GET /admin HTTP/1.1\" 403 1 \"-\" \"x\"").orElseThrow();
        assertEquals(403, webLine.status());

        SyslogParser.Message m = syslog.parseMessage("<34>1 2026-10-21T02:14:01Z host app 1 ID47 - hello");
        assertEquals(4, m.facility());
        assertEquals(2, m.severity());
        assertTrue(syslog.parse("<13>Oct 21 02:14:01 srv kernel: something").isEmpty());
        assertThrows(MalformedLogException.class, () -> syslog.parse("<999>Oct 21 02:14:01 srv sshd: x"));
    }

    @Test
    void hostileInputIsRejectedNotCrashed() {
        assertThrows(MalformedLogException.class, () -> ssh.parse("x".repeat(10_240)));
        assertThrows(MalformedLogException.class, () -> web.parse("x".repeat(10_240)));
        assertThrows(MalformedLogException.class, () -> ssh.parse(new String(new byte[] {0, 1, 2, (byte) 0xFF, 7, 8}, StandardCharsets.ISO_8859_1)));
        assertThrows(MalformedLogException.class, () -> web.parse("\u0000\u0001garbage"));
        assertThrows(MalformedLogException.class, () -> ssh.parse(""));
        assertThrows(MalformedLogException.class,
                () -> ssh.parse("Oct 21 02:14:01 srv sshd[1]: Failed password for root from not-an-ip port 1 ssh2"));
    }

    @Test
    void windowsEventsFromARootlessExport() throws Exception {
        Path file = dir.resolve("security.xml");
        Files.writeString(file, event(4625, "Administrator", "203.0.113.45", "<Data Name='Status'>0xc000006d</Data>")
                + event(4624, "alice", "198.51.100.10", "<Data Name='LogonType'>10</Data>")
                + event(4740, "bob", "-", "")
                + event(4688, "x", "-", ""));
        List<LogEvent> events = new WindowsEventXmlSource().parse(file);
        assertEquals(3, events.size(), "4688 is not a logon event and is skipped");
        assertEquals(Action.FAILED_LOGIN, events.get(0).action());
        assertEquals("203.0.113.45", events.get(0).ip());
        assertEquals("logon type 10", events.get(1).detail());
        assertEquals(Action.ACCOUNT_LOCKOUT, events.get(2).action());
        assertNull(events.get(2).ip());
        assertEquals(Instant.parse("2026-10-21T02:14:01.1234567Z"), events.get(0).timestamp());
    }

    @Test
    void windowsExportInUtf16FromPowerShellIsRead() throws Exception {
        Path file = dir.resolve("ps.xml");
        byte[] body = event(4625, "x", "203.0.113.1", "").getBytes(StandardCharsets.UTF_16LE);
        byte[] withBom = new byte[body.length + 2];
        withBom[0] = (byte) 0xFF;
        withBom[1] = (byte) 0xFE;
        System.arraycopy(body, 0, withBom, 2, body.length);
        Files.write(file, withBom);
        assertEquals(1, new WindowsEventXmlSource().parse(file).size());
    }

    @Test
    void xmlExternalEntityIsRejected() throws Exception {
        Path secret = dir.resolve("secret.txt");
        Files.writeString(secret, "TOP-SECRET");
        Path file = dir.resolve("evil.xml");
        Files.writeString(file, "<!DOCTYPE e [<!ENTITY xxe SYSTEM \"" + secret.toUri() + "\">]>"
                + event(4625, "&xxe;", "203.0.113.1", ""));
        MalformedLogException e = assertThrows(MalformedLogException.class, () -> new WindowsEventXmlSource().parse(file));
        assertFalse(e.getMessage().contains("TOP-SECRET"));
        Path entityOnly = dir.resolve("entity.xml");
        Files.writeString(entityOnly, event(4625, "&xxe;", "203.0.113.1", ""));
        assertThrows(MalformedLogException.class, () -> new WindowsEventXmlSource().parse(entityOnly), "undefined entity");
    }

    private Action action(String line) throws MalformedLogException {
        return ssh.parse(line).orElseThrow().action();
    }

    private static String event(int id, String user, String ip, String extra) {
        return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>" + id + "</EventID>"
                + "<TimeCreated SystemTime='2026-10-21T02:14:01.1234567Z'/></System><EventData>"
                + "<Data Name='TargetUserName'>" + user + "</Data><Data Name='IpAddress'>" + ip + "</Data>" + extra
                + "</EventData></Event>\r\n";
    }
}
