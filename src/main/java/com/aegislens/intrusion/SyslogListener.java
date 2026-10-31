package com.aegislens.intrusion;

import com.aegislens.util.CidrSet;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Receives syslog over the network: UDP datagrams (up to 8 KB) and TCP streams with newline or octet-counting framing
 * (RFC 6587). Safe defaults: binds to 127.0.0.1, accepts only allow-listed source addresses, at most 50 TCP connections
 * (one pool thread each), a 60 s idle timeout, 8 KB per message, and a token-bucket rate limit that drops the excess.
 * UDP syslog can be spoofed and lost: prefer TCP, and say so in the manual.
 */
public class SyslogListener {

    public static final int MAX_MESSAGE = 8192;
    public static final int MAX_CONNECTIONS = 50;
    public static final Duration IDLE_TIMEOUT = Duration.ofSeconds(60);
    private static final Logger LOG = Logger.getLogger(SyslogListener.class.getName());

    /** Where to listen; a port of -1 turns that protocol off, 0 picks a free port (tests). */
    public record Config(String bindAddress, int udpPort, int tcpPort, CidrSet allowedSources, double ratePerSecond) {
    }

    private final Config config;
    private final LineConsumer consumer;
    private final SourceCounters counters;
    private final TokenBucket bucket;
    private final Semaphore connectionSlots = new Semaphore(MAX_CONNECTIONS);
    private final ExecutorService connections = Executors.newFixedThreadPool(MAX_CONNECTIONS, r -> daemon(r, "aegislens-syslog-tcp"));
    private final AtomicLong rejected = new AtomicLong();
    private DatagramSocket udp;
    private ServerSocket tcp;
    private Thread udpThread;
    private Thread acceptThread;
    private volatile boolean running;

    public SyslogListener(Config config, LineConsumer consumer, SourceCounters counters) {
        this.config = config;
        this.consumer = consumer;
        this.counters = counters;
        this.bucket = new TokenBucket(config.ratePerSecond());
    }

    /** Opens the sockets and starts the receiving threads. */
    public synchronized void start() throws IOException {
        running = true;
        InetAddress bind = InetAddress.getByName(config.bindAddress());   // an address literal from config, not log text
        if (config.udpPort() >= 0) {
            udp = new DatagramSocket(new InetSocketAddress(bind, config.udpPort()));
            udpThread = daemon(this::receiveUdp, "aegislens-syslog-udp");
            udpThread.start();
        }
        if (config.tcpPort() >= 0) {
            tcp = new ServerSocket();
            tcp.bind(new InetSocketAddress(bind, config.tcpPort()));
            acceptThread = daemon(this::acceptTcp, "aegislens-syslog-accept");
            acceptThread.start();
        }
    }

    public int udpPort() {
        return udp == null ? -1 : udp.getLocalPort();
    }

    public int tcpPort() {
        return tcp == null ? -1 : tcp.getLocalPort();
    }

    /** Connections refused because of the allow-list or the connection limit. */
    public long rejectedConnections() {
        return rejected.get();
    }

    private void receiveUdp() {
        byte[] buf = new byte[MAX_MESSAGE];
        while (running) {
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            try {
                udp.receive(packet);
                if (allowed(packet.getAddress())) {
                    handle(new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8).strip());
                } else {
                    counters.dropped.incrementAndGet();
                }
            } catch (SocketException closed) {
                return;                                     // stop() closed the socket
            } catch (IOException e) {
                LOG.log(Level.FINE, "UDP receive failed", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void acceptTcp() {
        while (running) {
            Socket socket;
            try {
                socket = tcp.accept();
            } catch (IOException closed) {
                return;
            }
            if (!allowed(socket.getInetAddress()) || !connectionSlots.tryAcquire()) {
                rejected.incrementAndGet();
                closeQuietly(socket);
                continue;
            }
            connections.execute(() -> serve(socket));
        }
    }

    /** One TCP connection: reads frames until the peer closes or stays idle too long. */
    private void serve(Socket socket) {
        try {
            socket.setSoTimeout((int) IDLE_TIMEOUT.toMillis());
            InputStream in = new BufferedInputStream(socket.getInputStream());
            String frame;
            while (running && (frame = readFrame(in)) != null) {
                if (!frame.isBlank()) {
                    handle(frame);
                }
            }
        } catch (SocketTimeoutException idle) {
            LOG.fine("Closing idle syslog connection from " + socket.getInetAddress());
        } catch (IOException e) {
            LOG.log(Level.FINE, "Syslog connection ended", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            closeQuietly(socket);
            connectionSlots.release();
        }
    }

    /**
     * Reads one message: "123 &lt;34&gt;..." (octet counting: a length, a space, then that many bytes) or a line ending
     * in \n (newline framing). Anything longer than MAX_MESSAGE is skipped. Returns null at end of stream.
     */
    static String readFrame(InputStream in) throws IOException {
        in.mark(8);
        int first = in.read();
        if (first < 0) {
            return null;
        }
        if (Character.isDigit(first)) {
            int length = first - '0';
            int c;
            while ((c = in.read()) >= '0' && c <= '9' && length < MAX_MESSAGE * 10) {
                length = length * 10 + (c - '0');
            }
            if (c == ' ' && length > 0) {
                byte[] msg = in.readNBytes(Math.min(length, MAX_MESSAGE));
                if (length > msg.length && msg.length == MAX_MESSAGE) {
                    in.skipNBytes(length - msg.length);     // over-long frame: drop the rest so the next frame starts cleanly
                    return "";
                }
                return new String(msg, StandardCharsets.UTF_8);
            }
            in.reset();                                     // not a length prefix after all: treat as a line
        } else {
            in.reset();
        }
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int b;
        boolean tooLong = false;
        while ((b = in.read()) >= 0 && b != '\n') {
            if (line.size() < MAX_MESSAGE) {
                line.write(b);
            } else {
                tooLong = true;
            }
        }
        if (b < 0 && line.size() == 0) {
            return null;
        }
        return tooLong ? "" : line.toString(StandardCharsets.UTF_8).strip();
    }

    private void handle(String message) throws InterruptedException {
        counters.lines.incrementAndGet();
        counters.touch(Instant.now());
        if (!bucket.tryAcquire()) {
            counters.dropped.incrementAndGet();             // flood: drop and count
            return;
        }
        consumer.accept(message);
    }

    private boolean allowed(InetAddress address) {
        return config.allowedSources().size() == 0 || config.allowedSources().contains(address.getAddress());
    }

    /** Closes the sockets and waits for the threads to end. */
    public synchronized void stop() throws InterruptedException {
        running = false;
        if (udp != null) {
            udp.close();
        }
        if (tcp != null) {
            try {
                tcp.close();
            } catch (IOException ignored) {
                // closing anyway
            }
        }
        connections.shutdownNow();
        connections.awaitTermination(5, TimeUnit.SECONDS);
        for (Thread t : new Thread[] {udpThread, acceptThread}) {
            if (t != null) {
                t.join(5_000);
            }
        }
    }

    private static Thread daemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        return t;
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // nothing more to do
        }
    }
}
