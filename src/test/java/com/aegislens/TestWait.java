package com.aegislens;

import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.fail;

/** Waits for something another thread does (a tailer, the persister, a watcher), failing after 15 seconds. */
public final class TestWait {

    public static final long TIMEOUT_MS = 15_000;

    private TestWait() {
    }

    public static void until(BooleanSupplier condition, String what) throws InterruptedException {
        long deadline = System.currentTimeMillis() + TIMEOUT_MS;
        while (!condition.getAsBoolean()) {
            if (System.currentTimeMillis() > deadline) {
                fail("not reached within " + TIMEOUT_MS / 1000 + " s: " + what);
            }
            Thread.sleep(25);
        }
    }
}
