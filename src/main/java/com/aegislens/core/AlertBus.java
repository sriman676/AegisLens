package com.aegislens.core;

import java.util.LinkedList;
import java.util.List;

/**
 * Bounded buffer between producers (log tailers, scan tasks) and consumers (database writer, UI).
 * Written by hand with synchronized + wait/notifyAll on purpose, so the hand-off between threads is easy to follow.
 */
public class AlertBus {

    private final LinkedList<Finding> queue = new LinkedList<>();
    private final int capacity;
    private boolean closed;

    public AlertBus(int capacity) {
        if (capacity < 1) {
            throw new IllegalArgumentException("capacity must be at least 1");
        }
        this.capacity = capacity;
    }

    public AlertBus() {
        this(1000);
    }

    /** Adds a finding; waits while the buffer is full. */
    public synchronized void publish(Finding finding) throws InterruptedException {
        while (queue.size() >= capacity && !closed) {
            wait();
        }
        if (closed) {
            throw new IllegalStateException("AlertBus is closed");
        }
        queue.addLast(finding);
        notifyAll();
    }

    /** Removes the oldest finding; waits while empty. Returns null once the bus is closed and drained. */
    public synchronized Finding take() throws InterruptedException {
        while (queue.isEmpty()) {
            if (closed) {
                return null;
            }
            wait();
        }
        Finding f = queue.removeFirst();
        notifyAll();
        return f;
    }

    /**
     * Moves up to max queued findings into out without waiting (used after take() to build a batch).
     * Returns how many were moved. Wakes producers that wait for free space.
     */
    public synchronized int drainTo(List<Finding> out, int max) {
        int moved = 0;
        while (moved < max && !queue.isEmpty()) {
            out.add(queue.removeFirst());
            moved++;
        }
        if (moved > 0) {
            notifyAll();
        }
        return moved;
    }

    /** No more findings will be published; wakes every waiting thread. */
    public synchronized void close() {
        closed = true;
        notifyAll();
    }

    public synchronized int size() {
        return queue.size();
    }
}
