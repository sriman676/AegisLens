package com.aegislens.ai;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Iterator;

/**
 * Limits paid cloud AI calls per hour and per day, so a busy day or a bug cannot
 * run up a bill. Only calls that would really go out count; cached answers and the offline templates are free.
 */
public final class LlmBudget {

    public static final int DEFAULT_PER_HOUR = 30;
    public static final int DEFAULT_PER_DAY = 200;

    /** How much is used, for the AI view's counter. */
    public record Usage(int lastHour, int perHour, int lastDay, int perDay) {
    }

    private final int perHour;
    private final int perDay;
    private final Clock clock;
    private final ArrayDeque<Instant> calls = new ArrayDeque<>();

    public LlmBudget(int perHour, int perDay, Clock clock) {
        this.perHour = Math.max(0, perHour);
        this.perDay = Math.max(0, perDay);
        this.clock = clock;
    }

    public static LlmBudget unlimited() {
        return new LlmBudget(Integer.MAX_VALUE, Integer.MAX_VALUE, Clock.systemUTC());
    }

    /** Takes one call from the budget if there is room. */
    public synchronized boolean tryAcquire() {
        Usage u = usage();
        if (u.lastHour() >= perHour || u.lastDay() >= perDay) {
            return false;
        }
        calls.addLast(clock.instant());
        return true;
    }

    public synchronized Usage usage() {
        Instant now = clock.instant();
        Iterator<Instant> it = calls.iterator();
        while (it.hasNext() && it.next().isBefore(now.minus(Duration.ofDays(1)))) {
            it.remove();
        }
        int hour = 0;
        for (Instant t : calls) {
            if (!t.isBefore(now.minus(Duration.ofHours(1)))) {
                hour++;
            }
        }
        return new Usage(hour, perHour, calls.size(), perDay);
    }
}
