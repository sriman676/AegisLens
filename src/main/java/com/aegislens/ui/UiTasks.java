package com.aegislens.ui;

import javafx.application.Platform;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Runs slow work (database, files, network) on a daemon thread and hands the result or the error back to the JavaFX
 * thread with Platform.runLater, so the window never freezes.
 */
final class UiTasks {

    private static final Logger LOG = Logger.getLogger(UiTasks.class.getName());

    /** Work that returns a value and may fail. */
    @FunctionalInterface
    interface Work<T> {
        T call() throws Exception;
    }

    private UiTasks() {
    }

    /** Runs {@code work} in the background; {@code onDone} or {@code onError} then runs on the FX thread. */
    static <T> void run(String name, Work<T> work, Consumer<T> onDone, Consumer<Exception> onError) {
        Thread t = new Thread(() -> {
            try {
                T result = work.call();
                Platform.runLater(() -> onDone.accept(result));
            } catch (Exception e) {
                LOG.log(Level.WARNING, name + " failed", e);
                Platform.runLater(() -> onError.accept(e));
            }
        }, "aegislens-ui-" + name);
        t.setDaemon(true);
        t.start();
    }

    /** Waits for a job started elsewhere (for example by ScanCoordinator); errors arrive unwrapped from ExecutionException. */
    static <T> void await(String name, Future<T> job, Consumer<T> onDone, Consumer<Exception> onError) {
        run(name, () -> {
            try {
                return job.get();
            } catch (ExecutionException e) {
                throw e.getCause() instanceof Exception cause ? cause : e;
            }
        }, onDone, onError);
    }
}
