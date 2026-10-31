package com.aegislens.intrusion;

import com.aegislens.TestWait;
import com.aegislens.core.Finding;
import com.aegislens.util.CidrSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** R5: tailing, rotation, truncation, restart, syslog over loopback, flood limit, silence alert (I8, I10). */
class MonitoringTest {

    @TempDir
    Path dir;

    @Test
    void newLinesArriveAndPartialLinesWaitForTheirNewline() throws Exception {
        Path log = dir.resolve("app.log");
        Files.writeString(log, "old line that existed before\n");
        List<String> got = Collections.synchronizedList(new ArrayList<>());
        LogTailer t = tailer(log, got::add, OffsetStore.inMemory(), false);
        try {
            TestWait.until(t::caughtUp, "condition");
            append(log, "first\nsec");
            TestWait.until(() -> got.size() == 1, "condition");
            assertEquals(List.of("first"), got, "the old line is skipped (start at end), 'sec' is still partial");
            append(log, "ond\r\n");
            TestWait.until(() -> got.size() == 2, "condition");
            assertEquals("second", got.get(1));
        } finally {
            stop(t);
        }
        assertEquals(Thread.State.TERMINATED, t.getState());
    }

    @Test
    void renameRotationThenTruncationLosesAndRepeatsNothing() throws Exception {
        Path log = dir.resolve("auth.log");
        Files.writeString(log, "");
        List<String> got = Collections.synchronizedList(new ArrayList<>());
        LogTailer t = tailer(log, got::add, OffsetStore.inMemory(), false);
        try {
            TestWait.until(t::caughtUp, "condition");
            append(log, "1\n2\n3\n");
            TestWait.until(() -> got.size() == 3, "condition");
            Files.move(log, dir.resolve("auth.log.1"), StandardCopyOption.ATOMIC_MOVE);     // logrotate "create" style
            Files.writeString(log, "4 after rotation\n5\n");
            TestWait.until(() -> got.size() == 5, "condition");
            Files.writeString(log, "", StandardOpenOption.TRUNCATE_EXISTING);           // copytruncate style
            append(log, "6 after truncate\n");
            TestWait.until(() -> got.size() == 6, "condition");
        } finally {
            stop(t);
        }
        assertEquals(List.of("1", "2", "3", "4 after rotation", "5", "6 after truncate"), got);
    }

    @Test
    void restartContinuesFromTheSavedOffset() throws Exception {
        Path log = dir.resolve("web.log");
        Files.writeString(log, "");
        OffsetStore offsets = OffsetStore.inMemory();
        List<String> got = Collections.synchronizedList(new ArrayList<>());
        LogTailer first = tailer(log, got::add, offsets, false);
        TestWait.until(first::caughtUp, "condition");
        append(log, "a\nb\n");
        TestWait.until(() -> got.size() == 2, "condition");
        stop(first);
        append(log, "c written while stopped\n");
        LogTailer second = tailer(log, got::add, offsets, false);
        try {
            TestWait.until(() -> got.size() == 3, "condition");
            Thread.sleep(LogTailer.POLL.toMillis() * 2);
        } finally {
            stop(second);
        }
        assertEquals(List.of("a", "b", "c written while stopped"), got, "nothing lost, nothing repeated");
    }

    @Test
    void linesWrittenWhileStoppedAreReadEvenIfTheFirstRunSawNothing() throws Exception {
        Path log = dir.resolve("quiet-then-busy.log");
        Files.writeString(log, "");
        OffsetStore offsets = OffsetStore.inMemory();
        List<String> got = Collections.synchronizedList(new ArrayList<>());
        LogTailer first = tailer(log, got::add, offsets, false);
        TestWait.until(first::caughtUp, "condition");
        stop(first);                                         // read nothing at all
        append(log, "attack 1\nattack 2\n");                // written while AegisLens was closed
        LogTailer second = tailer(log, got::add, offsets, false);
        try {
            TestWait.until(() -> got.size() == 2, "condition");
        } finally {
            stop(second);
        }
        assertEquals(List.of("attack 1", "attack 2"), got);
    }

    @Test
    void overlongLinesAreSkippedAndCounted() throws Exception {
        Path log = dir.resolve("big.log");
        Files.writeString(log, "");
        List<String> got = Collections.synchronizedList(new ArrayList<>());
        LogTailer t = tailer(log, got::add, OffsetStore.inMemory(), false);
        try {
            TestWait.until(t::caughtUp, "condition");
            append(log, "x".repeat(20_000) + "\nafter\n");
            TestWait.until(() -> got.size() == 1, "condition");
            assertEquals("after", got.get(0));
            assertEquals(1, t.overlongLines());
        } finally {
            stop(t);
        }
    }

    @Test
    void appendedAttackRaisesAFindingWithinTwoSecondsI8() throws Exception {
        Path log = dir.resolve("auth.log");
        Files.writeString(log, "");
        DetectionEngine engine = new DetectionEngine(Thresholds.defaults(ZoneOffset.UTC), new CidrSet(), new CidrSet());
        List<Finding> found = Collections.synchronizedList(new ArrayList<>());
        SourceCounters counters = new SourceCounters();
        LogTailer t = new LogTailer(log, engine.consumerFor(new SshLogSource(), found::add, counters), OffsetStore.inMemory(), false, counters);
        t.start();
        try {
            TestWait.until(t::caughtUp, "condition");
            StringBuilder lines = new StringBuilder();
            for (int i = 0; i < 5; i++) {
                lines.append("Oct 21 02:14:0").append(i).append(" srv sshd[1]: Failed password for root from 203.0.113.45 port ")
                        .append(50000 + i).append(" ssh2\n");
            }
            long start = System.nanoTime();
            append(log, lines.toString());
            TestWait.until(() -> !found.isEmpty(), "condition");
            long ms = (System.nanoTime() - start) / 1_000_000;
            assertTrue(ms < 2_000, "took " + ms + " ms");
            assertEquals("NET-001", found.get(0).ruleId());
            assertEquals(5, counters.events.get());
        } finally {
            stop(t);
        }
    }

    @Test
    void twoTailersAtOnceLoseNothingI10() throws Exception {
        Path a = dir.resolve("a.log");
        Path b = dir.resolve("b.log");
        Files.writeString(a, "");
        Files.writeString(b, "");
        List<String> got = Collections.synchronizedList(new ArrayList<>());
        LogTailer ta = tailer(a, got::add, OffsetStore.inMemory(), false);
        LogTailer tb = tailer(b, got::add, OffsetStore.inMemory(), false);
        try {
            TestWait.until(() -> ta.caughtUp() && tb.caughtUp(), "condition");
            for (int i = 0; i < 200; i++) {
                append(a, "a" + i + "\n");
                append(b, "b" + i + "\n");
            }
            TestWait.until(() -> got.size() == 400, "condition");
            Thread.sleep(LogTailer.POLL.toMillis() * 2);
        } finally {
            stop(ta);
            stop(tb);
        }
        assertEquals(400, got.size());
        assertEquals(400, got.stream().distinct().count(), "no duplicates");
    }

    @Test
    void syslogOverUdpAndTcpWithBothFramings() throws Exception {
        String octet = "<38>1 2026-10-21T02:14:01Z srv sshd 1 - - octet framed";
        List<String> got = Collections.synchronizedList(new ArrayList<>());
        SyslogListener listener = new SyslogListener(
                new SyslogListener.Config("127.0.0.1", 0, 0, loopbackOnly(), 1000), got::add, new SourceCounters());
        listener.start();
        try {
            try (DatagramSocket udp = new DatagramSocket()) {
                byte[] msg = "<38>Oct 21 02:14:01 srv sshd[1]: hello udp".getBytes(StandardCharsets.UTF_8);
                udp.send(new DatagramPacket(msg, msg.length, InetAddress.getLoopbackAddress(), listener.udpPort()));
            }
            try (Socket tcp = new Socket("127.0.0.1", listener.tcpPort()); OutputStream out = tcp.getOutputStream()) {
                out.write(("<38>Oct 21 02:14:01 srv sshd[1]: newline framed\n"
                        + octet.getBytes(StandardCharsets.UTF_8).length + " " + octet).getBytes(StandardCharsets.UTF_8));
                out.flush();
                TestWait.until(() -> got.size() == 3, "condition");
            }
        } finally {
            listener.stop();
        }
        assertTrue(got.contains("<38>Oct 21 02:14:01 srv sshd[1]: hello udp"));
        assertTrue(got.contains("<38>Oct 21 02:14:01 srv sshd[1]: newline framed"));
        assertTrue(got.contains(octet));
    }

    @Test
    void floodIsRateLimitedAndOversizeFramesAreSkipped() throws Exception {
        List<String> got = Collections.synchronizedList(new ArrayList<>());
        SourceCounters counters = new SourceCounters();
        SyslogListener listener = new SyslogListener(
                new SyslogListener.Config("127.0.0.1", -1, 0, loopbackOnly(), 50), got::add, counters);
        listener.start();
        try (Socket tcp = new Socket("127.0.0.1", listener.tcpPort()); OutputStream out = tcp.getOutputStream()) {
            StringBuilder flood = new StringBuilder();
            flood.append("x".repeat(20_000)).append('\n');
            for (int i = 0; i < 2_000; i++) {
                flood.append("<13>Oct 21 02:14:01 srv app: flood ").append(i).append('\n');
            }
            out.write(flood.toString().getBytes(StandardCharsets.UTF_8));
            out.flush();
            TestWait.until(() -> counters.lines.get() >= 2_000, "condition");
        } finally {
            listener.stop();
        }
        assertTrue(counters.dropped.get() > 1_000, "dropped " + counters.dropped.get());
        assertTrue(got.size() <= 200, "accepted " + got.size() + " (about one second's worth plus refill)");
        assertTrue(got.stream().noneMatch(s -> s.startsWith("xxx")), "the 20 KB line was skipped");
    }

    @Test
    void silentSourceRaisesMon001Once() throws Exception {
        Path log = dir.resolve("quiet.log");
        Files.writeString(log, "");
        List<Finding> found = Collections.synchronizedList(new ArrayList<>());
        Clock later = Clock.offset(Clock.systemUTC(), Duration.ofMinutes(20));
        MonitorManager.Config cfg = new MonitorManager.Config(List.of(log), List.of(), false, "127.0.0.1", -1, -1, "",
                100, Duration.ofMinutes(15), ZoneOffset.UTC);
        MonitorManager m = new MonitorManager(cfg, new DetectionEngine(Thresholds.defaults(ZoneOffset.UTC), new CidrSet(), new CidrSet()),
                found::add, OffsetStore.inMemory(), later);
        m.start();
        try {
            m.checkSilence();
            m.checkSilence();
            assertEquals(1, found.size());
            assertEquals("MON-001", found.get(0).ruleId());
            assertEquals(1, m.status().size());
            assertTrue(List.of("RUNNABLE", "TIMED_WAITING").contains(m.status().get(0).state()));
        } finally {
            m.stop();
        }
        assertEquals("TERMINATED", m.status().get(0).state());
    }

    @Test
    void filesCanBeAddedAndRemovedWhileRunning() throws Exception {
        Path log = dir.resolve("added.log");
        Files.writeString(log, "Oct 21 02:14:00 srv sshd[1]: Failed password for root from 203.0.113.45 port 50000 ssh2\n");
        List<Finding> found = Collections.synchronizedList(new ArrayList<>());
        MonitorManager.Config cfg = new MonitorManager.Config(List.of(), List.of(), false, "127.0.0.1", -1, -1, "",
                100, Duration.ZERO, ZoneOffset.UTC);
        MonitorManager m = new MonitorManager(cfg, new DetectionEngine(Thresholds.defaults(ZoneOffset.UTC), new CidrSet(), new CidrSet()),
                found::add, OffsetStore.inMemory(), Clock.systemUTC());
        m.start();
        try {
            m.addFile(log, LogType.SSH, true);
            assertThrows(IllegalArgumentException.class, () -> m.addFile(log, LogType.SSH, false), "no duplicates");
            assertThrows(IllegalArgumentException.class, () -> m.addFile(dir.resolve("x.xml"), LogType.WINDOWS_XML, false));
            TestWait.until(() -> m.status().get(0).lines() == 1, "condition");              // fromStart = true read the existing line
            assertTrue(m.removeFile(log));
            assertTrue(m.status().isEmpty());
            assertFalse(m.removeFile(log), "already removed");
        } finally {
            m.stop();
        }
    }

    private static CidrSet loopbackOnly() {
        CidrSet set = new CidrSet();
        set.add("127.0.0.0/8");
        set.add("::1");
        return set;
    }

    private static LogTailer tailer(Path log, LineConsumer consumer, OffsetStore offsets, boolean fromStart) {
        LogTailer t = new LogTailer(log, consumer, offsets, fromStart, new SourceCounters());
        t.start();
        return t;
    }

    private static void stop(LogTailer t) throws InterruptedException {
        t.stopTailing();
        t.join(5_000);
    }

    private static void append(Path log, String text) throws Exception {
        Files.writeString(log, text, StandardOpenOption.APPEND);
    }

}
