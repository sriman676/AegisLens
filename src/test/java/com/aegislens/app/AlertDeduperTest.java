package com.aegislens.app;

import com.aegislens.core.Finding;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class AlertDeduperTest {

    /** A clock the test moves by hand. */
    static final class FakeClock extends Clock {
        private Instant now;

        FakeClock(Instant start) {
            this.now = start;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }

    @Test
    void firstPassesRepeatsAreCountedAndTheNextWindowCarriesTheCount() {
        FakeClock clock = new FakeClock(Instant.parse("2026-10-29T02:00:00Z"));
        AlertDeduper deduper = new AlertDeduper(Duration.ofMinutes(10), clock, 100);
        assertTrue(deduper.offer(brute("203.0.113.9")).isPresent(), "02:00 first one passes");
        clock.advance(Duration.ofMinutes(1));
        assertTrue(deduper.offer(brute("203.0.113.9")).isEmpty(), "02:01 repeat dropped");
        clock.advance(Duration.ofMinutes(4));
        assertTrue(deduper.offer(brute("203.0.113.9")).isEmpty(), "02:05 repeat dropped");
        assertTrue(deduper.offer(brute("198.51.100.1")).isPresent(), "another target is a different key");
        clock.advance(Duration.ofMinutes(6));
        Optional<Finding> after = deduper.offer(brute("203.0.113.9"));
        assertTrue(after.isPresent(), "02:11 cooldown over");
        assertEquals("3", after.get().evidence().get(AlertDeduper.COUNT_EVIDENCE));
        assertEquals(2, deduper.droppedTotal());
        clock.advance(Duration.ofMinutes(11));
        assertNull(deduper.offer(brute("203.0.113.9")).orElseThrow().evidence().get("count"), "no repeats: no count");
    }

    @Test
    void forgetsTheLeastRecentlySeenKeysBeyondTheLimit() {
        FakeClock clock = new FakeClock(Instant.parse("2026-10-29T02:00:00Z"));
        AlertDeduper deduper = new AlertDeduper(Duration.ofMinutes(10), clock, 2);
        deduper.offer(brute("a"));
        deduper.offer(brute("b"));
        deduper.offer(brute("a"));                  // touch a, so b is now the eldest
        deduper.offer(brute("c"));                  // evicts b
        assertEquals(2, deduper.trackedKeys());
        assertTrue(deduper.offer(brute("b")).isPresent(), "b was forgotten, so it passes again");
        assertTrue(deduper.offer(brute("c")).isEmpty(), "c is still remembered (a was evicted when b came back)");
    }

    @Test
    void anEscalationToAHigherSeverityIsNeverDropped() {
        FakeClock clock = new FakeClock(Instant.parse("2026-10-29T02:00:00Z"));
        AlertDeduper deduper = new AlertDeduper(Duration.ofMinutes(10), clock, 100);
        assertTrue(deduper.offer(brute("203.0.113.45")).isPresent());
        Finding critical = new Finding("ssh", "203.0.113.45", "NET-001", 90, "login after brute force");
        assertTrue(deduper.offer(critical).isPresent(), "same rule and target, but CRITICAL instead of HIGH");
        assertTrue(deduper.offer(critical).isEmpty());
    }

    private static Finding brute(String target) {
        return new Finding("ssh", target, "NET-001", 72, "brute force");
    }
}
