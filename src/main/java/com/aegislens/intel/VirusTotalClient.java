package com.aegislens.intel;

import com.aegislens.core.Finding;
import com.aegislens.db.VtCacheRepository;
import com.aegislens.db.VtResult;
import com.aegislens.intrusion.TokenBucket;
import com.aegislens.net.BoundedBody;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Optional VirusTotal hash lookups with the user's own key (env VT_API_KEY), only when the analyst asks. Only the
 * SHA-256 is sent, never the file. Answers are cached for 7 days (404 = "unknown to VirusTotal", also cached).
 * The free public API allows 4 lookups per minute and 500 per day, so requests go through one worker thread with a
 * token bucket and a daily counter; callers get a CompletableFuture and can see how many lookups are queued (N15).
 * The public API must not be used in commercial products: this is a student/personal tool.
 */
public final class VirusTotalClient implements AutoCloseable {

    public static final String DEFAULT_BASE = "https://www.virustotal.com";
    public static final Duration CACHE_FOR = Duration.ofDays(7);
    public static final int PER_MINUTE = 4;
    public static final int PER_DAY = 500;
    public static final String RULE = "MAL-005";
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
    private static final Logger LOG = Logger.getLogger(VirusTotalClient.class.getName());
    private static final ObjectMapper JSON = new ObjectMapper();

    /** Why a lookup failed. */
    public static final class VtException extends Exception {
        public enum Kind { NOT_CONFIGURED, AUTH, QUOTA, NETWORK, BAD_RESPONSE }

        private final Kind kind;

        public VtException(Kind kind, String message) {
            super(message);
            this.kind = kind;
        }

        public Kind kind() {
            return kind;
        }
    }

    private record Job(String sha256, CompletableFuture<VtResult> result) {
    }

    private final String apiKey;
    private final String baseUrl;
    private final HttpClient client;
    private final VtCacheRepository cache;
    private final TokenBucket perMinute;
    private final int perDay;
    private final Clock clock;
    private final BlockingQueue<Job> queue = new LinkedBlockingQueue<>();
    private final Thread worker;
    private volatile boolean running = true;
    private LocalDate day;
    private int usedToday;

    public VirusTotalClient(String apiKey, String baseUrl, HttpClient client, VtCacheRepository cache,
                            TokenBucket perMinute, int perDay, Clock clock) {
        this.apiKey = apiKey;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.client = client;
        this.cache = cache;
        this.perMinute = perMinute;
        this.perDay = perDay;
        this.clock = clock;
        this.worker = new Thread(this::run, "aegislens-virustotal");
        worker.setDaemon(true);
        worker.setPriority(Thread.MIN_PRIORITY);
        if (enabled()) {
            worker.start();
        }
    }

    /** Production limits: 4 per minute (bucket of 4 refilling at 4/60 per second), 500 per day. */
    public static VirusTotalClient standard(String apiKey, HttpClient client, VtCacheRepository cache) {
        return new VirusTotalClient(apiKey, DEFAULT_BASE, client, cache,
                new TokenBucket(PER_MINUTE, PER_MINUTE / 60.0, System::nanoTime), PER_DAY, Clock.systemUTC());
    }

    public boolean enabled() {
        return apiKey != null && !apiKey.isBlank();
    }

    /** Lookups waiting for the rate limit. */
    public int queued() {
        return queue.size();
    }

    /** The answer for this SHA-256: from the cache if fresh, otherwise queued for VirusTotal. */
    public CompletableFuture<VtResult> lookup(String sha256) {
        CompletableFuture<VtResult> f = new CompletableFuture<>();
        String sha = sha256 == null ? "" : sha256.trim().toLowerCase(java.util.Locale.ROOT);
        if (!enabled()) {
            f.completeExceptionally(new VtException(VtException.Kind.NOT_CONFIGURED, "No VirusTotal key (VT_API_KEY) set"));
            return f;
        }
        if (!SHA256.matcher(sha).matches()) {
            f.completeExceptionally(new IllegalArgumentException("not a SHA-256"));
            return f;
        }
        Optional<VtResult> cached = fresh(sha);
        if (cached.isPresent()) {
            f.complete(cached.get());
            return f;
        }
        queue.add(new Job(sha, f));
        return f;
    }

    private Optional<VtResult> fresh(String sha) {
        try {
            return cache.find(sha).filter(r -> r.checkedAt().isAfter(clock.instant().minus(CACHE_FOR)));
        } catch (SQLException e) {
            return Optional.empty();
        }
    }

    private void run() {
        while (running) {
            try {
                Job job = queue.take();
                Optional<VtResult> cached = fresh(job.sha256());       // an earlier job may have fetched it meanwhile
                if (cached.isPresent()) {
                    job.result().complete(cached.get());
                    continue;
                }
                if (!takeDailySlot()) {
                    job.result().completeExceptionally(new VtException(VtException.Kind.QUOTA, "Daily VirusTotal limit (" + perDay + ") reached"));
                    continue;
                }
                while (!perMinute.tryAcquire()) {
                    Thread.sleep(100);                                  // wait for the per-minute limit
                }
                fetch(job);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                failAll();
                return;
            }
        }
    }

    private synchronized boolean takeDailySlot() {
        LocalDate today = LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
        if (!today.equals(day)) {
            day = today;
            usedToday = 0;
        }
        if (usedToday >= perDay) {
            return false;
        }
        usedToday++;
        return true;
    }

    private void fetch(Job job) throws InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/api/v3/files/" + job.sha256()))
                .timeout(Duration.ofSeconds(20)).header("x-apikey", apiKey).GET().build();
        try {
            HttpResponse<String> r = client.send(request, BoundedBody.ofString(BoundedBody.LLM_LIMIT));
            BoundedBody.requireBody(r, BoundedBody.LLM_LIMIT);
            switch (r.statusCode()) {
                case 200 -> job.result().complete(store(parse(job.sha256(), r.body())));
                case 404 -> job.result().complete(store(new VtResult(job.sha256(), false, 0, 0, 0, clock.instant())));
                case 401, 403 -> job.result().completeExceptionally(new VtException(VtException.Kind.AUTH, "VirusTotal refused the key"));
                case 429 -> job.result().completeExceptionally(new VtException(VtException.Kind.QUOTA, "VirusTotal quota exceeded"));
                default -> job.result().completeExceptionally(new VtException(VtException.Kind.NETWORK, "VirusTotal answered HTTP " + r.statusCode()));
            }
        } catch (IOException e) {
            job.result().completeExceptionally(new VtException(VtException.Kind.NETWORK, "VirusTotal could not be reached"));
        } catch (VtException e) {
            job.result().completeExceptionally(e);
        }
    }

    private VtResult parse(String sha, String body) throws VtException {
        try {
            JsonNode stats = JSON.readTree(body).path("data").path("attributes").path("last_analysis_stats");
            if (!stats.isObject()) {
                throw new VtException(VtException.Kind.BAD_RESPONSE, "VirusTotal reply had no analysis statistics");
            }
            int total = 0;
            for (Map.Entry<String, JsonNode> engineCount : stats.properties()) {
                total += engineCount.getValue().asInt(0);
            }
            return new VtResult(sha, true, stats.path("malicious").asInt(0), stats.path("suspicious").asInt(0), total, clock.instant());
        } catch (IOException e) {
            throw new VtException(VtException.Kind.BAD_RESPONSE, "VirusTotal reply was not JSON");
        }
    }

    private VtResult store(VtResult r) {
        try {
            cache.save(r);
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Could not cache the VirusTotal answer", e);
        }
        return r;
    }

    /** MAL-005 (the README rule table): at least threshold engines say malicious; 1-2 -> 50, 3-9 -> 70, 10 or more -> 90. */
    public static Optional<Finding> finding(VtResult r, String target, int threshold) {
        if (!r.known() || r.malicious() < Math.max(1, threshold)) {
            return Optional.empty();
        }
        int score = r.malicious() >= 10 ? 90 : r.malicious() >= 3 ? 70 : 50;
        return Optional.of(new Finding("virustotal", target, RULE, score,
                r.malicious() + " of " + r.total() + " antivirus engines on VirusTotal flag this file",
                Map.of("sha256", r.sha256(), "malicious", String.valueOf(r.malicious()),
                        "suspicious", String.valueOf(r.suspicious()), "engines", String.valueOf(r.total())), null));
    }

    private void failAll() {
        Job j;
        while ((j = queue.poll()) != null) {
            j.result().completeExceptionally(new VtException(VtException.Kind.NETWORK, "shutting down"));
        }
    }

    @Override
    public void close() throws InterruptedException {
        running = false;
        worker.interrupt();
        if (worker.isAlive()) {
            worker.join(5_000);
        }
        failAll();
    }
}
