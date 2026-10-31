package com.aegislens.intrusion;

import com.aegislens.core.Finding;
import com.aegislens.util.CidrSet;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Starts and stops all live sources from one MonitorConfig: a LogTailer per SSH or web log file and the optional syslog
 * listener. Reports per-source status (thread state, lines, events, drops, last activity) and raises a LOW MON-001
 * finding when a source has been silent longer than the configured time (a stopped log is itself suspicious).
 */
public class MonitorManager {

    public static final String SILENCE_RULE = "MON-001";
    static final int SILENCE_SCORE = 20;
    static final Duration WATCHDOG_PERIOD = Duration.ofSeconds(30);
    private static final Logger LOG = Logger.getLogger(MonitorManager.class.getName());

    /** What to monitor. Ports of -1 disable syslog; silence of zero disables the silence alert. */
    public record Config(List<Path> sshFiles, List<Path> webFiles, boolean startAtBeginning, String syslogBind,
                         int syslogUdpPort, int syslogTcpPort, String syslogAllow, double syslogRatePerSecond,
                         Duration silence, ZoneId zone) {

        public boolean hasSources() {
            return !sshFiles.isEmpty() || !webFiles.isEmpty() || syslogUdpPort >= 0 || syslogTcpPort >= 0;
        }
    }

    /** One line of the status view. */
    public record SourceStatus(String name, String state, long lines, long events, long malformed, long dropped,
                               long findings, Instant lastActivity) {
    }

    private final Config config;
    private final DetectionEngine engine;
    private final DetectionEngine.FindingSink sink;
    private final OffsetStore offsets;
    private final Clock clock;
    private final Vector<LogTailer> tailers = new Vector<>();
    private final Map<String, Instant> silenceReported = new HashMap<>();
    private SyslogListener syslog;
    private SourceCounters syslogCounters;
    private ScheduledExecutorService watchdog;

    public MonitorManager(Config config, DetectionEngine engine, DetectionEngine.FindingSink sink, OffsetStore offsets, Clock clock) {
        this.config = config;
        this.engine = engine;
        this.sink = sink;
        this.offsets = offsets;
        this.clock = clock;
    }

    public synchronized void start() throws IOException {
        for (Path p : config.sshFiles()) {
            startTailer(p, new SshLogSource(clock, config.zone()));
        }
        for (Path p : config.webFiles()) {
            startTailer(p, new WebLogSource());
        }
        if (config.syslogUdpPort() >= 0 || config.syslogTcpPort() >= 0) {
            startSyslog();
        }
        if (!config.silence().isZero()) {
            watchdog = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "aegislens-monitor-watchdog");
                t.setDaemon(true);
                t.setPriority(Thread.MIN_PRIORITY);
                return t;
            });
            watchdog.scheduleAtFixedRate(this::checkSilence, WATCHDOG_PERIOD.toSeconds(), WATCHDOG_PERIOD.toSeconds(), TimeUnit.SECONDS);
        }
    }

    private void startTailer(Path file, LogSource source) {
        startTailer(file, source, config.startAtBeginning());
    }

    private void startTailer(Path file, LogSource source, boolean fromStart) {
        SourceCounters counters = new SourceCounters();
        LogTailer t = new LogTailer(file, engine.consumerFor(source, sink, counters), offsets, fromStart, counters);
        tailers.add(t);
        t.start();
    }

    /**
     * Starts tailing one more file while the app runs (Live Monitor view). Only SSH and WEB logs can be tailed; a file
     * that is already tailed is refused. {@code fromStart} reads the existing lines first, otherwise only new lines.
     */
    public synchronized void addFile(Path file, LogType type, boolean fromStart) {
        Path target = file.toAbsolutePath().normalize();
        if (tailers.stream().anyMatch(t -> t.file().toAbsolutePath().normalize().equals(target))) {
            throw new IllegalArgumentException(target + " is already monitored");
        }
        switch (type) {
            case SSH -> startTailer(target, new SshLogSource(clock, config.zone()), fromStart);
            case WEB -> startTailer(target, new WebLogSource(), fromStart);
            default -> throw new IllegalArgumentException(type.label() + " cannot be tailed; use Replay or the syslog listener");
        }
    }

    /** Stops tailing one file and forgets it. Returns false if it was not monitored. */
    public boolean removeFile(Path file) throws InterruptedException {
        LogTailer found;
        synchronized (this) {
            Path target = file.toAbsolutePath().normalize();
            found = tailers.stream().filter(t -> t.file().toAbsolutePath().normalize().equals(target)).findFirst().orElse(null);
            if (found == null) {
                return false;
            }
            tailers.remove(found);
        }
        found.stopTailing();
        found.join(5_000);                   // waited for outside the lock, so status() is never blocked
        return true;
    }

    private void startSyslog() throws IOException {
        CidrSet allowed = new CidrSet();
        for (String entry : config.syslogAllow().split(",")) {
            if (!entry.isBlank() && !allowed.add(entry.trim())) {
                LOG.warning("Ignoring syslog allow-list entry " + entry);
            }
        }
        syslogCounters = new SourceCounters();
        SyslogParser parser = new SyslogParser(new SshLogSource(clock, config.zone()), new WebLogSource(), clock, config.zone());
        syslog = new SyslogListener(new SyslogListener.Config(config.syslogBind(), config.syslogUdpPort(), config.syslogTcpPort(),
                allowed, config.syslogRatePerSecond()), engine.consumerFor(parser, sink, syslogCounters), syslogCounters);
        syslog.start();
    }

    /** Status of every source, for the UI and logs. */
    public synchronized List<SourceStatus> status() {
        List<SourceStatus> list = new ArrayList<>();
        for (LogTailer t : tailers) {
            SourceCounters c = t.counters();
            list.add(new SourceStatus(t.file().toString(), t.getState().name(), c.lines.get(), c.events.get(),
                    c.malformed.get(), c.dropped.get(), c.findings.get(), c.lastActivity()));
        }
        if (syslog != null) {
            SourceCounters c = syslogCounters;
            list.add(new SourceStatus("syslog udp:" + syslog.udpPort() + " tcp:" + syslog.tcpPort(), "LISTENING",
                    c.lines.get(), c.events.get(), c.malformed.get(), c.dropped.get(), c.findings.get(), c.lastActivity()));
        }
        return list;
    }

    public SyslogListener syslog() {
        return syslog;
    }

    public List<LogTailer> tailers() {
        return List.copyOf(tailers);
    }

    /** Raises MON-001 once per silence period for every source with no lines for longer than config.silence(). */
    synchronized void checkSilence() {
        Instant now = clock.instant();
        for (SourceStatus s : status()) {
            Instant last = s.lastActivity();
            Instant reported = silenceReported.get(s.name());
            boolean silent = last.isBefore(now.minus(config.silence()));
            if (silent && (reported == null || reported.isBefore(last))) {
                silenceReported.put(s.name(), now);
                publishSilence(s, now);
            }
        }
    }

    private void publishSilence(SourceStatus s, Instant now) {
        Finding f = new Finding("monitor", s.name(), SILENCE_RULE, SILENCE_SCORE,
                "No log lines from " + s.name() + " for more than " + config.silence().toMinutes() + " minutes",
                Map.of("lastActivity", s.lastActivity().toString()), now);
        try {
            sink.accept(f);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Stops the watchdog, every tailer and the listener, and waits for their threads. */
    public synchronized void stop() throws InterruptedException {
        if (watchdog != null) {
            watchdog.shutdownNow();
        }
        for (LogTailer t : tailers) {
            t.stopTailing();
        }
        for (LogTailer t : tailers) {
            t.join(5_000);
        }
        if (syslog != null) {
            try {
                syslog.stop();
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "Stopping the syslog listener failed", e);
            }
        }
    }
}
