package com.aegislens.app;

import com.aegislens.core.Finding;
import com.aegislens.core.Severity;
import com.aegislens.net.RetryPolicy;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Posts important findings to a chat webhook (Slack- and Discord-compatible JSON {"text": "..."}):
 * only findings at or above the configured severity; HTTPS only unless explicitly allowed; a bounded queue so a slow
 * webhook can never block detection (overflow is dropped and counted); 5 s timeout with retries; the text is capped at
 * 1 000 characters and never contains raw log lines. The URL is a secret: it comes from AEGISLENS_WEBHOOK_URL and is
 * shown masked., Jackson JSON.
 */
public final class WebhookNotifier implements AutoCloseable {

    public static final int QUEUE_SIZE = 100;
    public static final int MAX_TEXT = 1000;
    public static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final Logger LOG = Logger.getLogger(WebhookNotifier.class.getName());
    private static final ObjectMapper JSON = new ObjectMapper();

    private final URI url;
    private final Severity minimum;
    private final HttpClient client;
    private final RetryPolicy retry;
    private final BlockingQueue<Finding> queue = new ArrayBlockingQueue<>(QUEUE_SIZE);
    private final Thread worker;
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong failed = new AtomicLong();
    private volatile boolean running = true;

    public WebhookNotifier(URI url, Severity minimum, boolean allowHttp, HttpClient client, RetryPolicy retry) {
        if (!"https".equalsIgnoreCase(url.getScheme()) && !(allowHttp && "http".equalsIgnoreCase(url.getScheme()))) {
            throw new IllegalArgumentException("webhook URL must use https");
        }
        this.url = url;
        this.minimum = minimum;
        this.client = client;
        this.retry = retry;
        this.worker = new Thread(this::run, "aegislens-webhook");
        worker.setDaemon(true);
        worker.start();
    }

    /** Called for every saved finding; never blocks. */
    public void offer(Finding f) {
        if (f.severity().ordinal() >= minimum.ordinal() && !queue.offer(f)) {
            dropped.incrementAndGet();
        }
    }

    private void run() {
        while (running) {
            try {
                Finding f = queue.take();
                send(f);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void send(Finding f) throws InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(url).timeout(TIMEOUT)
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload(f))).build();
        try {
            HttpResponse<Void> r = retry.execute(() -> client.send(request, HttpResponse.BodyHandlers.discarding()));
            if (r.statusCode() / 100 == 2) {
                sent.incrementAndGet();
            } else {
                failed.incrementAndGet();
                LOG.warning("Webhook answered HTTP " + r.statusCode());
            }
        } catch (IOException e) {
            failed.incrementAndGet();
            LOG.log(Level.WARNING, "Webhook could not be reached", e);
        }
    }

    /** {"text": "[AegisLens] HIGH 72 NET-001 203.0.113.45: ..."} without raw log lines, capped. */
    static String payload(Finding f) {
        StringBuilder text = new StringBuilder("[AegisLens] ").append(f.severity()).append(' ').append(f.score())
                .append(' ').append(f.ruleId()).append(' ').append(f.target()).append(": ").append(f.description());
        for (Map.Entry<String, String> e : f.evidence().entrySet()) {
            if (!e.getKey().equals("line")) {
                text.append(" | ").append(e.getKey()).append('=').append(e.getValue());
            }
        }
        String capped = text.length() <= MAX_TEXT ? text.toString() : text.substring(0, MAX_TEXT - 1) + "…";
        try {
            return JSON.writeValueAsString(Map.of("text", capped.replaceAll("\\p{Cntrl}", " ")));
        } catch (IOException e) {
            throw new IllegalStateException("a map of strings is always serialisable", e);
        }
    }

    /** "https://hooks.example.com/…f3a9" for display: the full URL is a secret. */
    public static String mask(URI url) {
        String s = url.toString();
        return url.getScheme() + "://" + url.getHost() + "/…" + s.substring(Math.max(0, s.length() - 4));
    }

    public long sentCount() {
        return sent.get();
    }

    public long droppedCount() {
        return dropped.get();
    }

    public long failedCount() {
        return failed.get();
    }

    @Override
    public void close() throws InterruptedException {
        running = false;
        worker.interrupt();
        worker.join(TIMEOUT.toMillis());
    }
}
