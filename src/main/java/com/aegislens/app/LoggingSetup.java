package com.aegislens.app;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Sends java.util.logging output of all com.aegislens classes to rotating files in the data folder:
 * aegislens-0.log (newest) to aegislens-4.log, 1 MB each. Never logs secrets (they are never in config or the DB).
 */
public final class LoggingSetup {

    public static final int FILE_LIMIT_BYTES = 1_000_000;
    public static final int FILE_COUNT = 5;
    public static final String PATTERN = "aegislens-%g.log";

    private static final Logger ROOT = Logger.getLogger("com.aegislens");
    private static FileHandler installed;

    private LoggingSetup() {
    }

    /** Installs the rotating file handler once; calling it again does nothing. */
    public static synchronized void install(Path logsDir) throws IOException {
        if (installed != null) {
            return;
        }
        Files.createDirectories(logsDir);
        FileHandler handler = new FileHandler(logsDir.resolve(PATTERN).toString(), FILE_LIMIT_BYTES, FILE_COUNT, true);
        handler.setFormatter(new SimpleFormatter());
        ROOT.addHandler(handler);
        installed = handler;
    }

    /** Removes and closes the file handler (at shutdown, and between tests). */
    public static synchronized void uninstall() {
        if (installed != null) {
            ROOT.removeHandler(installed);
            installed.close();
            installed = null;
        }
    }

    static synchronized boolean isInstalled() {
        for (Handler h : ROOT.getHandlers()) {
            if (h == installed && h != null) {
                return true;
            }
        }
        return false;
    }
}
