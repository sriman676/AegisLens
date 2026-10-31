package com.aegislens.ui;

import com.aegislens.core.Finding;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Hands live findings from the persister thread to the dashboard without flooding the FX thread (G5): the persister
 * only adds to a lock-free queue; the dashboard takes at most {@link #BATCH} every {@link #PERIOD_MS} ms. During an
 * attack the queue keeps at most {@link #MAX_QUEUED}; older ones are dropped here (they are still in the database).
 * Plain Java, so it is unit-tested without JavaFX.
 */
public final class FindingsFeed {

    public static final int PERIOD_MS = 250;
    public static final int BATCH = 200;
    public static final int MAX_QUEUED = 5_000;

    private final ConcurrentLinkedQueue<Finding> queue = new ConcurrentLinkedQueue<>();
    private final AtomicInteger size = new AtomicInteger();
    private final AtomicLong dropped = new AtomicLong();

    /** Called on the persister thread for every saved finding. */
    public void offer(Finding f) {
        queue.add(f);
        if (size.incrementAndGet() > MAX_QUEUED && queue.poll() != null) {
            size.decrementAndGet();
            dropped.incrementAndGet();
        }
    }

    /** Called on the FX thread: up to BATCH findings, oldest first. */
    public List<Finding> drain() {
        List<Finding> batch = new ArrayList<>();
        Finding f;
        while (batch.size() < BATCH && (f = queue.poll()) != null) {
            size.decrementAndGet();
            batch.add(f);
        }
        return batch;
    }

    /** Findings that never reached the live table (they are in the database and the Findings view). */
    public long dropped() {
        return dropped.get();
    }
}
