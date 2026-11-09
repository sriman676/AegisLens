package com.aegislens.siem;

import com.aegislens.core.Finding;
import com.aegislens.core.Severity;
import com.aegislens.net.FakeServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLServerSocket;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class SiemForwarderTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-10T08:30:00Z"), ZoneOffset.UTC);

    private static Finding finding(int score) {
        return new Finding("intrusion", "203.0.113.45", "NET-001", score, "5 failed SSH logins", null, CLOCK.instant());
    }

    private static SiemForwarder.Settings syslog(int port, SiemForwarder.Protocol p, SiemForwarder.Format f, String pin) {
        return new SiemForwarder.Settings("127.0.0.1", port, p, f, Severity.LOW, pin, null);
    }

    private static SiemForwarder forwarder(SiemForwarder.Settings s) throws Exception {
        return new SiemForwarder(s, "1.0.0", "pc1", CLOCK, Duration.ofMillis(10));
    }

    /** Collects newline-framed lines from every accepted connection. */
    private static Thread collect(ServerSocket server, BlockingQueue<String> lines) {
        Thread t = new Thread(() -> {
            while (!server.isClosed()) {
                try (Socket s = server.accept();
                     BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8))) {
                    for (String line; (line = in.readLine()) != null; ) {
                        lines.add(line);
                    }
                } catch (Exception closed) {
                    // next connection or end of test
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }

    @Test
    void udpSendsOneCefMessagePerDatagram() throws Exception {
        try (DatagramSocket server = new DatagramSocket(0, InetAddress.getLoopbackAddress());
             SiemForwarder f = forwarder(syslog(server.getLocalPort(), SiemForwarder.Protocol.UDP, SiemForwarder.Format.CEF, null))) {
            server.setSoTimeout(5000);
            f.offer(finding(72));
            DatagramPacket p = new DatagramPacket(new byte[4096], 4096);
            server.receive(p);
            String msg = new String(p.getData(), 0, p.getLength(), StandardCharsets.UTF_8);
            assertTrue(msg.startsWith("<83>1 2026-11-10T08:30:00Z pc1 aegislens - FINDING - CEF:0|AegisLens|AegisLens|1.0.0|NET-001|"), msg);
        }
    }

    @Test
    void tcpSendsNewlineFramedJsonAndReconnectsAfterTheServerDropsIt() throws Exception {
        BlockingQueue<String> lines = new LinkedBlockingQueue<>();
        try (ServerSocket server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress());
             SiemForwarder f = forwarder(syslog(server.getLocalPort(), SiemForwarder.Protocol.TCP, SiemForwarder.Format.JSON, null))) {
            collect(server, lines);
            f.offer(finding(40));
            f.offer(finding(90));
            String first = lines.poll(5, TimeUnit.SECONDS);
            assertNotNull(first);
            assertTrue(first.contains(" FINDING - {\"@timestamp\":\"2026-11-10T08:30:00Z\""), first);
            assertNotNull(lines.poll(5, TimeUnit.SECONDS));
            assertEquals(2, f.sentCount());
        }
    }

    @Test
    void tlsWithAPinnedCertificateDelivers() throws Exception {
        BlockingQueue<String> lines = new LinkedBlockingQueue<>();
        try (SSLServerSocket server = (SSLServerSocket) FakeServer.serverTls().getServerSocketFactory()
                .createServerSocket(0, 5, InetAddress.getLoopbackAddress());
             SiemForwarder f = forwarder(syslog(server.getLocalPort(), SiemForwarder.Protocol.TLS, SiemForwarder.Format.CEF,
                     FakeServer.certificatePin()))) {
            collect(server, lines);
            f.offer(finding(72));
            String line = lines.poll(10, TimeUnit.SECONDS);
            assertNotNull(line, "last error: " + f.lastError());
            assertTrue(line.contains("CEF:0|AegisLens"));
        }
    }

    @Test
    void tlsRefusesACertificateThatIsNotPinnedOrTrusted() throws Exception {
        BlockingQueue<String> lines = new LinkedBlockingQueue<>();
        String wrongPin = "00".repeat(32);
        try (SSLServerSocket server = (SSLServerSocket) FakeServer.serverTls().getServerSocketFactory()
                .createServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            collect(server, lines);
            for (String pin : new String[] {wrongPin, null}) {         // wrong pin; self-signed against the Java trust store
                try (SiemForwarder f = forwarder(syslog(server.getLocalPort(), SiemForwarder.Protocol.TLS, SiemForwarder.Format.CEF, pin))) {
                    f.offer(finding(72));
                    long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                    while (f.failedCount() == 0 && System.nanoTime() < end) {
                        Thread.sleep(20);
                    }
                    assertEquals(1, f.failedCount());
                    assertEquals(0, f.sentCount());
                }
            }
            assertTrue(lines.isEmpty());
        }
    }

    @Test
    void unreachableSiemCountsAFailureAndNeverBlocks() throws Exception {
        int closedPort;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            closedPort = s.getLocalPort();
        }
        try (SiemForwarder f = forwarder(syslog(closedPort, SiemForwarder.Protocol.TCP, SiemForwarder.Format.CEF, null))) {
            long start = System.nanoTime();
            for (int i = 0; i < SiemForwarder.QUEUE_SIZE + 50; i++) {
                f.offer(finding(50));
            }
            assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(1), "offer must never wait for the network");
            long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (f.failedCount() == 0 && System.nanoTime() < end) {
                Thread.sleep(20);
            }
            assertTrue(f.failedCount() >= 1);
            assertTrue(f.droppedCount() >= 1);
            assertNotNull(f.lastError());
        }
    }

    @Test
    void fileGetsJsonLinesAndMinimumSeverityFilters(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("out").resolve("findings.jsonl");
        SiemForwarder.Settings s = new SiemForwarder.Settings("", 0, SiemForwarder.Protocol.TCP, SiemForwarder.Format.CEF,
                Severity.HIGH, null, file);
        try (SiemForwarder f = forwarder(s)) {
            f.offer(finding(10));                                   // LOW: below siem.min.severity
            f.offer(finding(72));
            assertTrue(f.sendTest(CLOCK), "the test event ignores the minimum");
            assertTrue(f.drain(Duration.ofSeconds(5)));
        }
        List<String> lines = Files.readAllLines(file);
        assertEquals(2, lines.size(), lines.toString());
        assertTrue(lines.get(0).startsWith("{\"@timestamp\""));
        assertTrue(lines.get(1).contains("\"TEST-000\""));
    }

    @Test
    void settingsMustNameADestinationAndAValidPort() {
        assertThrows(IllegalArgumentException.class, () -> forwarder(new SiemForwarder.Settings("", 514,
                SiemForwarder.Protocol.TCP, SiemForwarder.Format.CEF, Severity.LOW, null, null)));
        assertThrows(IllegalArgumentException.class, () -> forwarder(syslog(0, SiemForwarder.Protocol.UDP, SiemForwarder.Format.CEF, null)));
        assertEquals("tls://siem:6514 (CEF) + file x.jsonl", new SiemForwarder.Settings("siem", 6514, SiemForwarder.Protocol.TLS,
                SiemForwarder.Format.CEF, Severity.LOW, null, Path.of("x.jsonl")).describe());
    }
}
