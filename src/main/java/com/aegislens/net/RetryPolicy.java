package com.aegislens.net;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

/**
 * Retries an HTTP call that failed for a temporary reason: HTTP 429, 500, 502, 503, 504 or an IOException
 * such as a timeout. Waits base x 2^(attempt-1) plus random jitter between attempts, or what the server's Retry-After
 * header asks for (capped). Other 4xx answers (bad key, bad request) are never retried: repeating them cannot help.
 * The sleeper is injectable so tests run instantly.
 */
public final class RetryPolicy {

    public static final int DEFAULT_ATTEMPTS = 3;
    public static final Duration DEFAULT_BASE = Duration.ofMillis(500);
    public static final Duration MAX_WAIT = Duration.ofSeconds(30);
    static final Set<Integer> RETRYABLE = Set.of(429, 500, 502, 503, 504);

    /** Waits; Thread::sleep in production, a recorder in tests. */
    @FunctionalInterface
    public interface Sleeper {
        void sleep(Duration d) throws InterruptedException;
    }

    /** One attempt of the request. */
    @FunctionalInterface
    public interface Call<T> {
        HttpResponse<T> send() throws IOException, InterruptedException;
    }

    private final int maxAttempts;
    private final Duration base;
    private final Sleeper sleeper;
    private final Random random;

    public RetryPolicy(int maxAttempts, Duration base, Sleeper sleeper, Random random) {
        this.maxAttempts = Math.max(1, maxAttempts);
        this.base = base;
        this.sleeper = sleeper;
        this.random = random;
    }

    /** 3 attempts, 0.5 s base, real sleeping. */
    public static RetryPolicy standard() {
        return new RetryPolicy(DEFAULT_ATTEMPTS, DEFAULT_BASE, d -> Thread.sleep(d.toMillis()), new Random());
    }

    /** A single attempt (used when offline-safety matters more than persistence). */
    public static RetryPolicy none() {
        return new RetryPolicy(1, Duration.ZERO, d -> { }, new Random());
    }

    public int maxAttempts() {
        return maxAttempts;
    }

    /** Runs call, retrying temporary failures. Returns the last response (possibly an error status) or throws. */
    public <T> HttpResponse<T> execute(Call<T> call) throws IOException, InterruptedException {
        for (int attempt = 1; ; attempt++) {
            try {
                HttpResponse<T> response = call.send();
                if (!RETRYABLE.contains(response.statusCode()) || attempt >= maxAttempts) {
                    return response;
                }
                sleeper.sleep(delay(attempt, retryAfter(response)));
            } catch (IOException e) {
                if (attempt >= maxAttempts || e instanceof ResponseTooLargeException) {
                    throw e;
                }
                sleeper.sleep(delay(attempt, Optional.empty()));
            }
        }
    }

    Duration delay(int attempt, Optional<Duration> serverAsked) {
        if (serverAsked.isPresent()) {
            return min(serverAsked.get(), MAX_WAIT);
        }
        long exponential = base.toMillis() * (1L << Math.min(attempt - 1, 10));
        long jitter = base.isZero() ? 0 : (long) (random.nextDouble() * base.toMillis());
        return min(Duration.ofMillis(exponential + jitter), MAX_WAIT);
    }

    /** Retry-After as seconds ("120") or an HTTP date. */
    static Optional<Duration> retryAfter(HttpResponse<?> response) {
        Optional<String> header = response.headers().firstValue("retry-after");
        if (header.isEmpty()) {
            return Optional.empty();
        }
        String v = header.get().trim();
        try {
            return Optional.of(Duration.ofSeconds(Math.max(0, Long.parseLong(v))));
        } catch (NumberFormatException notSeconds) {
            try {
                ZonedDateTime when = ZonedDateTime.parse(v, DateTimeFormatter.RFC_1123_DATE_TIME);
                Duration d = Duration.between(ZonedDateTime.now(when.getZone()), when);
                return Optional.of(d.isNegative() ? Duration.ZERO : d);
            } catch (DateTimeParseException bad) {
                return Optional.empty();
            }
        }
    }

    private static Duration min(Duration a, Duration b) {
        return a.compareTo(b) <= 0 ? a : b;
    }
}
