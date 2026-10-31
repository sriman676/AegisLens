package com.aegislens.intrusion;

import java.util.function.LongSupplier;

/**
 * Rate limiter: a bucket holds up to capacity tokens and refills at ratePerSecond; each message takes one token, and a
 * message that finds the bucket empty is dropped (and counted by the caller). Protects the listener from floods.
 */
public final class TokenBucket {

    private static final double NANOS_PER_SECOND = 1_000_000_000.0;

    private final double capacity;
    private final double ratePerSecond;
    private final LongSupplier nanoClock;
    private double tokens;
    private long last;

    public TokenBucket(double capacity, double ratePerSecond, LongSupplier nanoClock) {
        if (capacity < 1 || ratePerSecond <= 0) {
            throw new IllegalArgumentException("capacity >= 1 and rate > 0 required");
        }
        this.capacity = capacity;
        this.ratePerSecond = ratePerSecond;
        this.nanoClock = nanoClock;
        this.tokens = capacity;
        this.last = nanoClock.getAsLong();
    }

    /** A bucket that allows bursts of up to one second's worth of messages. */
    public TokenBucket(double ratePerSecond) {
        this(ratePerSecond, ratePerSecond, System::nanoTime);
    }

    /** Takes one token if there is one. */
    public synchronized boolean tryAcquire() {
        long now = nanoClock.getAsLong();
        tokens = Math.min(capacity, tokens + (now - last) / NANOS_PER_SECOND * ratePerSecond);
        last = now;
        if (tokens >= 1) {
            tokens -= 1;
            return true;
        }
        return false;
    }
}
