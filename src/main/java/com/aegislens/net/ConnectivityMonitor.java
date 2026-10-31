package com.aegislens.net;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Background thread (MIN_PRIORITY) that asks "can we reach the cloud AI services?" every 30 seconds with a cheap
 * HEAD request. Any HTTP answer, even 404, means online; a timeout or refused connection means offline. While offline,
 * the explanation service skips cloud providers instantly instead of waiting for timeouts. It also
 * compares the server's Date header with our clock and warns when they differ by more than 5 minutes (N18).
 */
public class ConnectivityMonitor extends Thread {

    public static final Duration INTERVAL = Duration.ofSeconds(30);
    public static final Duration TIMEOUT = Duration.ofSeconds(5);
    public static final Duration SKEW_WARNING = Duration.ofMinutes(5);

    /** One check's result. clockSkew is server time minus our time (zero if unknown). */
    public record Status(boolean online, Duration latency, Instant checkedAt, Duration clockSkew, String detail) {

        public boolean clockWarning() {
            return clockSkew.abs().compareTo(SKEW_WARNING) > 0;
        }

        static Status unknown() {
            return new Status(false, Duration.ZERO, Instant.EPOCH, Duration.ZERO, "not checked yet");
        }
    }

    private final HttpClient client;
    private final List<URI> hosts;
    private final Clock clock;
    private final List<Consumer<Status>> listeners = new CopyOnWriteArrayList<>();
    private volatile Status current = Status.unknown();
    private volatile boolean running = true;

    public ConnectivityMonitor(HttpClient client, List<URI> hosts, Clock clock) {
        super("aegislens-connectivity");
        this.client = client;
        this.hosts = List.copyOf(hosts);
        this.clock = clock;
        setDaemon(true);
        setPriority(MIN_PRIORITY);           // a background check must never compete with the UI or the scans
    }

    public Status current() {
        return current;
    }

    public void addListener(Consumer<Status> listener) {
        listeners.add(listener);
    }

    public void stopMonitoring() {
        running = false;
        interrupt();
    }

    @Override
    public void run() {
        try {
            while (running) {
                checkNow();
                Thread.sleep(INTERVAL.toMillis());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Checks the hosts in order; the first that answers decides "online". Notifies listeners. */
    public Status checkNow() throws InterruptedException {
        Status s = new Status(false, Duration.ZERO, clock.instant(), Duration.ZERO, "no host reachable");
        for (URI host : hosts) {
            Instant start = clock.instant();
            try {
                HttpResponse<Void> r = client.send(HttpRequest.newBuilder(host).timeout(TIMEOUT)
                        .method("HEAD", HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.discarding());
                Instant end = clock.instant();
                s = new Status(true, Duration.between(start, end), end, skew(r, end), host.getHost() + " answered " + r.statusCode());
                break;
            } catch (IOException unreachable) {
                s = new Status(false, Duration.ZERO, clock.instant(), Duration.ZERO, host.getHost() + " unreachable");
            }
        }
        current = s;
        for (Consumer<Status> l : listeners) {
            l.accept(s);
        }
        return s;
    }

    private static Duration skew(HttpResponse<?> r, Instant now) {
        return r.headers().firstValue("date").map(d -> {
            try {
                return Duration.between(now, ZonedDateTime.parse(d, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant());
            } catch (DateTimeParseException bad) {
                return Duration.ZERO;
            }
        }).orElse(Duration.ZERO);
    }
}
