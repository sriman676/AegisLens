package com.aegislens.ui;

import javafx.animation.PauseTransition;
import javafx.application.Platform;
import javafx.util.Duration;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Makes a screen update by itself the moment something new arrives (a finding, a feed update), with no Refresh button:
 * any thread calls poke(); the action then runs on the FX thread after a short gap. Many pokes during the gap become ONE
 * update, so an attack with thousands of findings cannot flood the window.
 */
final class LiveRefresh {

    /** Shortest time between two updates of the same screen. */
    static final Duration GAP = Duration.millis(400);

    private final Runnable action;
    private final AtomicBoolean pending = new AtomicBoolean();

    LiveRefresh(Runnable action) {
        this.action = action;
    }

    /** Something changed: update soon (safe from any thread). */
    void poke() {
        if (pending.compareAndSet(false, true)) {
            Platform.runLater(() -> {
                PauseTransition wait = new PauseTransition(GAP);
                wait.setOnFinished(e -> {
                    pending.set(false);                 // pokes from now on schedule the next update
                    action.run();
                });
                wait.play();
            });
        }
    }
}
