package com.aegislens.sandbox;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * Reads a process's output on its own thread, keeps at most maxBytes, and keeps draining the rest so the
 * process never blocks on a full pipe.
 */
final class OutputCollector implements Runnable {

    private final InputStream in;
    private final int maxBytes;
    private final ByteArrayOutputStream kept = new ByteArrayOutputStream();
    private boolean truncated;

    OutputCollector(InputStream in, int maxBytes) {
        this.in = in;
        this.maxBytes = maxBytes;
    }

    /** What a watched process did: finished in time or not, how long it ran, and its (capped) output. */
    record Watched(boolean finished, long millis, String text, boolean truncated) {
    }

    /** What to do when the time limit is reached, before the process itself is destroyed. */
    @FunctionalInterface
    interface OnTimeout {
        void stop() throws IOException, InterruptedException;
    }

    /**
     * Shared by both sandboxes: no stdin, output read on its own thread with the policy's cap, wait for the time limit;
     * on timeout run onTimeout (kill the process tree or the container), then destroy the process for sure.
     */
    static Watched watch(Process process, long startNanos, SandboxPolicy policy, OnTimeout onTimeout)
            throws IOException, InterruptedException {
        process.getOutputStream().close();
        OutputCollector collector = new OutputCollector(process.getInputStream(), policy.maxOutputBytes());
        Thread reader = new Thread(collector, "sandbox-output");
        reader.setDaemon(true);
        reader.start();
        boolean finished = process.waitFor(policy.timeout().toMillis(), TimeUnit.MILLISECONDS);
        if (!finished) {
            onTimeout.stop();
            process.destroyForcibly();
            process.waitFor(5, TimeUnit.SECONDS);
        }
        reader.join(5000);
        return new Watched(finished, (System.nanoTime() - startNanos) / 1_000_000, collector.text(), collector.truncated());
    }

    @Override
    public void run() {
        byte[] buffer = new byte[4096];
        try {
            int n;
            while ((n = in.read(buffer)) != -1) {
                store(buffer, n);
            }
        } catch (IOException ignored) {
            // the process was killed or the pipe closed: keep what we have
        }
    }

    private synchronized void store(byte[] buffer, int n) {
        int room = maxBytes - kept.size();
        if (room > 0) {
            kept.write(buffer, 0, Math.min(room, n));
        }
        if (n > room) {
            truncated = true;
        }
    }

    synchronized String text() {
        return new String(kept.toByteArray(), StandardCharsets.UTF_8);
    }

    synchronized boolean truncated() {
        return truncated;
    }
}
