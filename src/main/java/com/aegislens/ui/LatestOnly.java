package com.aegislens.ui;

import java.util.function.Consumer;

/**
 * Keeps one screen's reloads from piling up: while a load runs, further requests are not started but remembered, and
 * only the newest one runs when the current load ends. With live updates a big database (a 1-second report) under
 * attack (a poke every 400 ms) would otherwise start more and more queries. Used only on the FX thread, so it needs no
 * locks.
 */
final class LatestOnly {

    private boolean running;
    private Runnable next;

    /** Like {@link UiTasks#run}, but at most one load at a time; a request made meanwhile replaces any older waiting one. */
    <T> void run(String name, UiTasks.Work<T> work, Consumer<T> onDone, Consumer<Exception> onError) {
        Runnable job = () -> UiTasks.run(name, work, result -> {
            onDone.accept(result);
            finished();
        }, e -> {
            onError.accept(e);
            finished();
        });
        if (running) {
            next = job;
            return;
        }
        running = true;
        job.run();
    }

    private void finished() {
        Runnable waiting = next;
        next = null;
        if (waiting == null) {
            running = false;
        } else {
            waiting.run();
        }
    }
}
