package com.aegislens.intrusion;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Live counters for one log source (a tailed file or the syslog listener), read by the UI's status view while the
 * source's own thread updates them. Atomic counters and a volatile time make that safe without locks.
 */
public final class SourceCounters {

    public final AtomicLong lines = new AtomicLong();
    public final AtomicLong events = new AtomicLong();
    public final AtomicLong malformed = new AtomicLong();
    public final AtomicLong dropped = new AtomicLong();
    public final AtomicLong findings = new AtomicLong();
    private volatile Instant lastActivity = Instant.now();

    /** Called for every line received, so a silent source can be noticed. */
    public void touch(Instant now) {
        lastActivity = now;
    }

    public Instant lastActivity() {
        return lastActivity;
    }
}
