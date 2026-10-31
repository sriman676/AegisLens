package com.aegislens.core;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class CoreTest {

    @Test
    void drainToMovesAtMostMaxWithoutWaiting() throws InterruptedException {
        AlertBus bus = new AlertBus(10);
        for (int i = 0; i < 5; i++) {
            bus.publish(new Finding("t", "x" + i, "R", 10, "d"));
        }
        List<Finding> out = new ArrayList<>();
        assertEquals(3, bus.drainTo(out, 3));
        assertEquals("x0", out.get(0).target(), "oldest first");
        assertEquals(2, bus.size());
        assertEquals(2, bus.drainTo(out, 10));
        assertEquals(0, bus.drainTo(out, 10), "empty bus returns at once");
    }

    @Test
    void severityBoundaries() {
        assertEquals(Severity.LOW, Severity.fromScore(0));
        assertEquals(Severity.LOW, Severity.fromScore(29));
        assertEquals(Severity.MEDIUM, Severity.fromScore(30));
        assertEquals(Severity.HIGH, Severity.fromScore(60));
        assertEquals(Severity.CRITICAL, Severity.fromScore(85));
        assertEquals(Severity.CRITICAL, Severity.fromScore(100));
        assertThrows(IllegalArgumentException.class, () -> Severity.fromScore(101));
        assertThrows(IllegalArgumentException.class, () -> Severity.fromScore(-1));
    }

    @Test
    void findingValidatesAndDerivesSeverity() {
        Finding f = new Finding("test", "203.0.113.45", "NET-001", 70, "5 failed logins");
        assertEquals(Severity.HIGH, f.severity());
        assertTrue(f.evidence().isEmpty());
        assertThrows(IllegalArgumentException.class, () -> new Finding("test", "x", "R", 101, "d"));
        assertThrows(IllegalArgumentException.class, () -> new Finding("", "x", "R", 10, "d"));
        assertThrows(UnsupportedOperationException.class, () -> f.evidence().put("a", "b"));
    }

    @Test
    void treeSetSortsMostSevereFirst() {
        TreeSet<Finding> set = new TreeSet<>();
        set.add(new Finding("t", "a", "R1", 10, "low"));
        set.add(new Finding("t", "b", "R2", 90, "critical", Map.of(), null));
        set.add(new Finding("t", "c", "R3", 65, "high"));
        assertEquals("R2", set.first().ruleId());
        assertEquals("R1", set.last().ruleId());
    }

    @Test
    void alertBusDeliversEverythingFromManyProducers() throws Exception {
        AlertBus bus = new AlertBus(10);          // small buffer forces producers to wait
        int producers = 3;
        int perProducer = 200;
        AtomicInteger received = new AtomicInteger();

        Thread consumer = new Thread(() -> {
            try {
                while (bus.take() != null) {
                    received.incrementAndGet();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        consumer.start();

        List<Thread> threads = new ArrayList<>();
        for (int p = 0; p < producers; p++) {
            final int id = p;
            Thread t = new Thread(() -> {
                try {
                    for (int i = 0; i < perProducer; i++) {
                        bus.publish(new Finding("p" + id, "t" + i, "R", 10, "d"));
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            threads.add(t);
            t.start();
        }
        for (Thread t : threads) {
            t.join(10_000);
        }
        bus.close();
        consumer.join(10_000);

        assertFalse(consumer.isAlive(), "consumer should stop after close()");
        assertEquals(producers * perProducer, received.get());
    }

    @Test
    void closedBusRejectsPublish() {
        AlertBus bus = new AlertBus();
        bus.close();
        assertThrows(IllegalStateException.class, () -> bus.publish(new Finding("t", "a", "R", 1, "d")));
    }
}
