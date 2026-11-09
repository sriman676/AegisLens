package com.aegislens.app;

import com.aegislens.db.AlreadyRunningException;
import com.aegislens.siem.SiemForwarder;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.DateTimeException;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/**
 * AegisLens without a window, for servers (R12): {@code java -jar aegislens.jar --headless [--config file]
 * [--key=value ...]}. It starts the same ScanCoordinator as the GUI (live log monitors, syslog, feeds, webhook,
 * maintenance) and runs until the process is stopped (Ctrl+C, systemd stop, or a Windows task end); a shutdown hook then
 * stops every thread in order and closes the database. This class must never load a JavaFX class.
 * Exit codes: 0 normal, 1 unexpected error, 2 configuration problem, 3 already running on this data folder.
 * Also: {@code --version} prints the version; {@code --check-config} checks the configuration and exits;
 * {@code --siem-test} sends one test finding to the configured SIEM and exits.
 */
public final class HeadlessMain {

    public static final String VERSION = "1.0.0";
    public static final int OK = 0;
    public static final int FAILED = 1;
    public static final int BAD_CONFIG = 2;
    public static final int ALREADY_RUNNING = 3;
    private static final List<String> PORT_KEYS = List.of("syslog.udp.port", "syslog.tcp.port");
    private static final List<String> NUMBER_KEYS = List.of("monitor.silence.minutes", "dedupe.cooldown.minutes",
            "scan.threads", "bus.capacity", "ai.budget.hour", "ai.budget.day");

    private HeadlessMain() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    /** Everything main does, without System.exit, so tests can call it. Blocks until shutdown for a normal start. */
    static int run(String[] args, PrintStream out, PrintStream err) {
        List<String> flags = Arrays.asList(args);
        if (flags.contains("--version")) {
            out.println("AegisLens " + VERSION + " (Java " + Runtime.version() + ")");
            return OK;
        }
        AppConfig config;
        try {
            config = load(args);
        } catch (IOException | IllegalArgumentException e) {
            err.println("Configuration error: " + e.getMessage());
            return BAD_CONFIG;
        }
        List<String> problems = problems(config);
        if (flags.contains("--check-config")) {
            problems.forEach(p -> out.println("problem: " + p));
            out.println(problems.isEmpty() ? "Configuration OK (data folder " + config.paths().dataDir() + ")" : problems.size() + " problem(s)");
            return problems.isEmpty() ? OK : BAD_CONFIG;
        }
        if (!problems.isEmpty()) {
            problems.forEach(p -> err.println("Configuration error: " + p));
            return BAD_CONFIG;
        }
        if (flags.contains("--siem-test")) {
            return siemTest(config, out, err);
        }
        return serve(config, out, err);
    }

    /** --siem-test: sends one test finding (TEST-000) to the configured SIEM and reports whether it was delivered. */
    static int siemTest(AppConfig config, PrintStream out, PrintStream err) {
        SiemForwarder.Settings settings = ScanCoordinator.siemSettings(config);
        if (!settings.anyOn()) {
            err.println("No SIEM configured: set siem.host (and siem.port, siem.protocol) and/or siem.file");
            return BAD_CONFIG;
        }
        try (SiemForwarder siem = new SiemForwarder(settings, VERSION, SiemForwarder.localHostName(), java.time.Clock.systemUTC())) {
            siem.sendTest(java.time.Clock.systemUTC());
            siem.drain(java.time.Duration.ofSeconds(30));
            Thread.sleep(200);
            if (siem.failedCount() > 0) {
                err.println("SIEM test failed (" + settings.describe() + "): " + siem.lastError());
                return FAILED;
            }
            out.println("SIEM test event sent to " + settings.describe() + ". Search your SIEM for TEST-000.");
            return OK;
        } catch (Exception e) {
            err.println("SIEM test failed: " + e.getMessage());
            return FAILED;
        }
    }

    /** --config file wins over the default data folder's aegislens.properties. */
    static AppConfig load(String[] args) throws IOException {
        List<String> rest = new ArrayList<>();
        Path file = null;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--config")) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("--config needs a file name");
                }
                file = Path.of(args[++i]);
                if (!Files.isReadable(file)) {
                    throw new IllegalArgumentException("cannot read " + file);
                }
            } else if (!args[i].equals("--headless") && !args[i].equals("--check-config") && !args[i].equals("--siem-test")) {
                rest.add(args[i]);
            }
        }
        String[] remaining = rest.toArray(new String[0]);
        return file == null ? AppConfig.load(remaining) : AppConfig.load(file, System.getenv(), remaining);
    }

    /** Problems that would stop a server from working; an empty list means the configuration is usable. */
    static List<String> problems(AppConfig config) {
        List<String> problems = new ArrayList<>();
        for (String key : PORT_KEYS) {
            int port = config.getInt(key, -1);
            if (port < -1 || port > 65535) {
                problems.add(key + " must be -1 (off) or 0..65535, not " + port);
            }
        }
        for (String key : NUMBER_KEYS) {
            String value = config.get(key, null);
            if (value != null && !value.strip().matches("\\d+")) {
                problems.add(key + " must be a whole number, not '" + value + "'");
            }
        }
        for (String key : List.of("oddhour.start", "oddhour.end")) {
            String time = config.get(key, null);
            if (time != null && !time.strip().matches("([01]\\d|2[0-3]):[0-5]\\d")) {
                problems.add(key + " must be a time like 22:00, not '" + time + "'");
            }
        }
        String zone = config.get("oddhour.zone", null);
        if (zone != null) {
            try {
                ZoneId.of(zone.strip());
            } catch (DateTimeException e) {
                problems.add("oddhour.zone '" + zone + "' is not a time zone (use for example Asia/Kolkata or UTC)");
            }
        }
        for (String key : List.of("monitor.ssh.files", "monitor.web.files")) {
            for (String f : config.get(key, "").split(",")) {
                if (!f.isBlank() && !Files.isReadable(Path.of(f.strip()))) {
                    problems.add(key + ": cannot read " + f.strip() + " (check the path and that this user may read it)");
                }
            }
        }
        try {
            ScanCoordinator.siemSettings(config);
        } catch (IllegalArgumentException e) {
            problems.add(e.getMessage());
        }
        String sysmon = config.get(ScanCoordinator.SYSMON_FOLDER, "").strip();
        if (!sysmon.isEmpty() && !Files.isDirectory(Path.of(sysmon))) {
            problems.add(ScanCoordinator.SYSMON_FOLDER + ": " + sysmon + " is not a folder");
        }
        return problems;
    }

    private static int serve(AppConfig config, PrintStream out, PrintStream err) {
        Running running;
        try {
            running = start(config);
        } catch (AlreadyRunningException e) {
            err.println("AegisLens is already running on " + config.paths().dataDir());
            return ALREADY_RUNNING;
        } catch (Exception e) {
            err.println("Could not start: " + e.getMessage());
            return FAILED;
        }
        Runtime.getRuntime().addShutdownHook(new Thread(running::stop, "aegislens-shutdown"));
        out.println("AegisLens " + VERSION + " running headless; data folder " + config.paths().dataDir() + ", "
                + running.coordinator().monitorStatus().size() + " live source(s). Stop with Ctrl+C.");
        running.awaitStop();
        return OK;
    }

    /** Opens the data folder (lock, database) and starts every service. */
    static Running start(AppConfig config) throws Exception {
        LoggingSetup.install(config.paths().logsDir());
        ScanCoordinator coordinator = new ScanCoordinator(config);
        coordinator.start();
        return new Running(coordinator);
    }

    /** A started headless instance. stop() is what the shutdown hook runs; awaitStop() blocks until it finished. */
    static final class Running {
        private final ScanCoordinator coordinator;
        private final CountDownLatch stopped = new CountDownLatch(1);

        Running(ScanCoordinator coordinator) {
            this.coordinator = coordinator;
        }

        ScanCoordinator coordinator() {
            return coordinator;
        }

        /** Stops monitors, scans, maintenance, bus and persister, then closes the database and the log files. */
        void stop() {
            try {
                coordinator.shutdown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                LoggingSetup.uninstall();
                stopped.countDown();
            }
        }

        void awaitStop() {
            try {
                stopped.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
