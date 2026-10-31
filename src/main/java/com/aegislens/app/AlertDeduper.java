package com.aegislens.app;

import com.aegislens.core.Finding;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Stops the same alert (same rule, target and severity) from flooding the analyst: the first one passes at once, repeats inside
 * the cooldown are counted and dropped, and the first one after the cooldown passes with evidence count=N
 * (N = the dropped repeats plus itself). Remembers at most maxKeys pairs, forgetting the least recently seen.
 */
public final class AlertDeduper {

    public static final int DEFAULT_MAX_KEYS = 10_000;
    public static final String COUNT_EVIDENCE = "count";

    /** Start of the current cooldown window and how many repeats were dropped in it. */
    private static final class Window {
        Instant start;
        int dropped;

        Window(Instant start) {
            this.start = start;
        }
    }

    private final Duration cooldown;
    private final Clock clock;
    private final Map<String, Window> windows;
    private long droppedTotal;

    public AlertDeduper(Duration cooldown, Clock clock, int maxKeys) {
        if (cooldown.isNegative() || maxKeys < 1) {
            throw new IllegalArgumentException("cooldown must be >= 0 and maxKeys >= 1");
        }
        this.cooldown = cooldown;
        this.clock = clock;
        this.windows = new LinkedHashMap<>(16, 0.75f, true) {     // access order: least recently seen first
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Window> eldest) {
                return size() > maxKeys;
            }
        };
    }

    public AlertDeduper(Duration cooldown) {
        this(cooldown, Clock.systemUTC(), DEFAULT_MAX_KEYS);
    }

    /** Returns the finding to forward (possibly a copy with count=N), or empty if it is a repeat to drop. */
    public synchronized Optional<Finding> offer(Finding f) {
        String key = f.ruleId() + '|' + f.target() + '|' + f.severity();      // a rise in severity is new information
        Instant now = clock.instant();
        Window w = windows.get(key);
        if (w == null) {
            windows.put(key, new Window(now));
            return Optional.of(f);
        }
        if (now.isBefore(w.start.plus(cooldown))) {
            w.dropped++;
            droppedTotal++;
            return Optional.empty();
        }
        int count = w.dropped + 1;
        w.start = now;
        w.dropped = 0;
        return Optional.of(count > 1 ? withCount(f, count) : f);
    }

    public synchronized long droppedTotal() {
        return droppedTotal;
    }

    public synchronized int trackedKeys() {
        return windows.size();
    }

    private static Finding withCount(Finding f, int count) {
        Map<String, String> evidence = new LinkedHashMap<>(f.evidence());
        evidence.put(COUNT_EVIDENCE, String.valueOf(count));
        return new Finding(f.source(), f.target(), f.ruleId(), f.score(), f.description(), evidence, f.timestamp());
    }
}
