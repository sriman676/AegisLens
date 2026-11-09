package com.aegislens.siem;

import com.aegislens.core.Finding;
import com.aegislens.core.Severity;
import com.aegislens.net.PinnedTrustManager;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Sends every saved finding to a SIEM: as syslog (RFC 5424, CEF or JSON payload) over UDP, TCP or TLS, and/or as JSON
 * lines appended to a file that a SIEM agent ships (Filebeat, Elastic Agent, Splunk Universal Forwarder, Wazuh agent).
 * Like the webhook it never blocks detection: a bounded queue (overflow is dropped and counted) and one worker thread.
 * A TCP/TLS connection is kept open and re-opened after a failure; a failed finding is retried a few times, then dropped
 * and counted. TLS uses the Java trust store and checks the host name, or trusts exactly one pinned certificate.
 */
public final class SiemForwarder implements AutoCloseable {

    public static final int QUEUE_SIZE = 1000;
    public static final int ATTEMPTS = 3;
    public static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    public static final long MAX_FILE_BYTES = 10L * 1024 * 1024;
    private static final Logger LOG = Logger.getLogger(SiemForwarder.class.getName());

    /** Where findings go. */
    public enum Protocol { UDP, TCP, TLS }

    /** Payload inside the syslog message. */
    public enum Format { CEF, JSON }

    /**
     * host empty = no syslog; file null = no JSON-lines file. pin: SHA-256 of the SIEM's certificate, or null to use the
     * Java trust store.
     */
    public record Settings(String host, int port, Protocol protocol, Format format, Severity minimum, String pin, Path file) {

        public boolean syslogOn() {
            return host != null && !host.isBlank();
        }

        public boolean anyOn() {
            return syslogOn() || file != null;
        }

        /** "tls://siem.local:6514 (CEF)" and/or "file C:\...\findings.jsonl" for the status line. */
        public String describe() {
            List<String> parts = new ArrayList<>();
            if (syslogOn()) {
                parts.add(protocol.name().toLowerCase(Locale.ROOT) + "://" + host + ':' + port + " (" + format + ")");
            }
            if (file != null) {
                parts.add("file " + file);
            }
            return String.join(" + ", parts);
        }
    }

    /** One destination. */
    interface Sink extends AutoCloseable {
        void send(Finding f) throws IOException;

        @Override
        void close();
    }

    private final Settings settings;
    private final List<Sink> sinks = new ArrayList<>();
    private final BlockingQueue<Finding> queue = new ArrayBlockingQueue<>(QUEUE_SIZE);
    private final Thread worker;
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong failed = new AtomicLong();
    private final Duration retryWait;
    private volatile String lastError;
    private volatile boolean running = true;

    public SiemForwarder(Settings settings, String version, String hostname, Clock clock) throws GeneralSecurityException {
        this(settings, version, hostname, clock, Duration.ofSeconds(2));
    }

    SiemForwarder(Settings settings, String version, String hostname, Clock clock, Duration retryWait) throws GeneralSecurityException {
        if (!settings.anyOn()) {
            throw new IllegalArgumentException("set siem.host and/or siem.file");
        }
        this.settings = settings;
        this.retryWait = retryWait;
        if (settings.syslogOn()) {
            if (settings.port() < 1 || settings.port() > 65535) {
                throw new IllegalArgumentException("siem.port must be 1..65535");
            }
            Formatter formatter = f -> SiemFormat.syslog(f, hostname, settings.format() == Format.CEF
                    ? SiemFormat.cef(f, version) : SiemFormat.json(f, version, hostname), clock.instant());
            sinks.add(settings.protocol() == Protocol.UDP ? new UdpSink(settings.host(), settings.port(), formatter)
                    : new StreamSink(settings, formatter));
        }
        if (settings.file() != null) {
            sinks.add(new FileSink(settings.file(), f -> SiemFormat.json(f, version, hostname)));
        }
        this.worker = new Thread(this::run, "aegislens-siem");
        worker.setDaemon(true);
        worker.start();
    }

    /** Called for every saved finding; never blocks. */
    public void offer(Finding f) {
        if (f.severity().ordinal() >= settings.minimum().ordinal() && !queue.offer(f)) {
            dropped.incrementAndGet();
        }
    }

    private void run() {
        while (running) {
            Finding f;
            try {
                f = queue.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            for (Sink sink : sinks) {
                if (!deliver(sink, f)) {
                    return;
                }
            }
        }
    }

    /** Tries ATTEMPTS times; false only when interrupted (shutting down). */
    private boolean deliver(Sink sink, Finding f) {
        for (int attempt = 1; attempt <= ATTEMPTS; attempt++) {
            try {
                sink.send(f);
                sent.incrementAndGet();
                lastError = null;
                return true;
            } catch (IOException e) {
                lastError = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                if (attempt == ATTEMPTS) {
                    failed.incrementAndGet();
                    LOG.log(Level.WARNING, "SIEM: could not deliver a finding after " + ATTEMPTS + " attempts", e);
                    return true;
                }
                try {
                    TimeUnit.MILLISECONDS.sleep(retryWait.toMillis() * attempt);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return true;
    }

    /** Queues one LOW test finding (TEST-000) regardless of siem.min.severity, to check the SIEM receives it. */
    public boolean sendTest(Clock clock) {
        Finding test = new Finding("siem-test", "aegislens", "TEST-000", 0,
                "AegisLens SIEM test event: if you can read this in your SIEM, forwarding works", null, clock.instant());
        return queue.offer(test);
    }

    /** COMPUTERNAME / HOSTNAME, else the local host name, else "-". */
    public static String localHostName() {
        for (String env : new String[] {"COMPUTERNAME", "HOSTNAME"}) {
            String v = System.getenv(env);
            if (v != null && !v.isBlank()) {
                return v.strip();
            }
        }
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (IOException e) {
            return "-";
        }
    }

    public Settings settings() {
        return settings;
    }

    /** Deliveries that reached a destination (one finding sent to syslog and the file counts twice). */
    public long sentCount() {
        return sent.get();
    }

    public long droppedCount() {
        return dropped.get();
    }

    public long failedCount() {
        return failed.get();
    }

    /** The last delivery error, or null after a success. */
    public String lastError() {
        return lastError;
    }

    /** Waits up to the timeout until everything queued so far was handled (tests, clean shutdown). */
    public boolean drain(Duration timeout) throws InterruptedException {
        long end = System.nanoTime() + timeout.toNanos();
        while (!queue.isEmpty() && System.nanoTime() < end) {
            Thread.sleep(20);
        }
        Thread.sleep(50);
        return queue.isEmpty();
    }

    @Override
    public void close() throws InterruptedException {
        drain(Duration.ofSeconds(2));
        running = false;
        worker.interrupt();
        worker.join(CONNECT_TIMEOUT.toMillis());
        sinks.forEach(Sink::close);
    }

    @FunctionalInterface
    interface Formatter {
        String format(Finding f);
    }

    /** RFC 5426: one message per datagram. */
    private static final class UdpSink implements Sink {
        private final String host;
        private final int port;
        private final Formatter formatter;
        private DatagramSocket socket;

        UdpSink(String host, int port, Formatter formatter) {
            this.host = host;
            this.port = port;
            this.formatter = formatter;
        }

        @Override
        public void send(Finding f) throws IOException {
            if (socket == null) {
                socket = new DatagramSocket();
            }
            byte[] bytes = formatter.format(f).getBytes(StandardCharsets.UTF_8);
            socket.send(new DatagramPacket(bytes, bytes.length, InetAddress.getByName(host), port));
        }

        @Override
        public void close() {
            if (socket != null) {
                socket.close();
            }
        }
    }

    /** TCP or TLS, one message per line (the framing rsyslog, syslog-ng, Splunk, Wazuh and Sentinel's AMA accept). */
    private static final class StreamSink implements Sink {
        private final Settings settings;
        private final Formatter formatter;
        private final SSLContext tls;
        private Socket socket;
        private OutputStream out;

        StreamSink(Settings settings, Formatter formatter) throws GeneralSecurityException {
            this.settings = settings;
            this.formatter = formatter;
            if (settings.protocol() == Protocol.TLS) {
                tls = SSLContext.getInstance("TLS");
                boolean pinned = settings.pin() != null && !settings.pin().isBlank();
                tls.init(null, pinned ? new TrustManager[] {new PinnedTrustManager(settings.pin())} : null, null);
            } else {
                tls = null;
            }
        }

        @Override
        public void send(Finding f) throws IOException {
            byte[] line = (formatter.format(f) + "\n").getBytes(StandardCharsets.UTF_8);
            try {
                connect();
                out.write(line);
                out.flush();
            } catch (IOException e) {
                close();                                  // re-open on the next attempt
                throw e;
            }
        }

        private void connect() throws IOException {
            if (socket != null && !socket.isClosed()) {
                return;
            }
            Socket plain = new Socket();
            try {
                plain.connect(new InetSocketAddress(settings.host(), settings.port()), (int) CONNECT_TIMEOUT.toMillis());
                plain.setKeepAlive(true);
                if (tls != null) {
                    SSLSocket s = (SSLSocket) tls.getSocketFactory().createSocket(plain, settings.host(), settings.port(), true);
                    SSLParameters p = s.getSSLParameters();
                    boolean pinned = settings.pin() != null && !settings.pin().isBlank();
                    if (!pinned) {
                        p.setEndpointIdentificationAlgorithm("HTTPS");    // host name must match the certificate
                    }
                    if (!SiemFormat.isIp(settings.host())) {
                        p.setServerNames(List.of(new SNIHostName(settings.host())));
                    }
                    s.setSSLParameters(p);
                    s.startHandshake();
                    socket = s;
                } else {
                    socket = plain;
                }
                out = socket.getOutputStream();
            } catch (IOException e) {
                plain.close();
                throw e;
            }
        }

        @Override
        public void close() {
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException ignored) {
                // already broken
            }
            socket = null;
            out = null;
        }
    }

    /** JSON lines for a SIEM agent; at MAX_FILE_BYTES the file is renamed to name.1 and a new one is started. */
    private static final class FileSink implements Sink {
        private final Path file;
        private final Formatter formatter;

        FileSink(Path file, Formatter formatter) {
            this.file = file;
            this.formatter = formatter;
        }

        @Override
        public void send(Finding f) throws IOException {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            if (Files.exists(file) && Files.size(file) > MAX_FILE_BYTES) {
                Files.move(file, file.resolveSibling(file.getFileName() + ".1"), StandardCopyOption.REPLACE_EXISTING);
            }
            try (BufferedWriter w = Files.newBufferedWriter(file, StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND)) {
                w.write(formatter.format(f));
                w.write('\n');
            }
        }

        @Override
        public void close() {
            // opened per finding
        }
    }
}
