package com.aegislens.intrusion;

import com.aegislens.core.Detector;
import com.aegislens.core.Finding;
import com.aegislens.core.MalformedLogException;
import com.aegislens.util.CidrSet;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Runs every enabled detector on each event and offers a replay of a whole log file (the "Replay log..." menu and the
 * acceptance tests). Shared by all sources, so process() is synchronized: detector state must see events one at a time.
 */
public final class DetectionEngine {

    private static final Logger LOG = Logger.getLogger(DetectionEngine.class.getName());
    private static final int CHUNK = 64 * 1024;

    /** Where findings go (the AlertBus in the app, a list in tests). */
    @FunctionalInterface
    public interface FindingSink {
        void accept(Finding finding) throws InterruptedException;
    }

    /** Counts from one replay. */
    public record ReplayResult(long lines, long events, long malformed, long overlong, long findings) {
    }

    private final List<Detector<LogEvent>> detectors = new ArrayList<>();         // guarded by this
    private CidrSet blocklist;
    private CidrSet commandAndControl;
    private ThreatIntelDetector threatIntel;

    /** The standard set of detectors for these thresholds (rules disabled in the rule table are left out). */
    public DetectionEngine(Thresholds t, CidrSet blocklist, CidrSet commandAndControl) {
        this.blocklist = blocklist;
        this.commandAndControl = commandAndControl;
        reconfigure(t);
    }

    /**
     * Rebuilds the detectors for new thresholds or enabled rules while monitors keep running (Settings > rules).
     * The per-IP counting windows start empty again, so an attack in progress is counted from this moment.
     */
    public synchronized void reconfigure(Thresholds t) {
        detectors.clear();
        threatIntel = new ThreatIntelDetector(blocklist, commandAndControl, t);
        addIfEnabled(t, new BruteForceDetector(t));
        addIfEnabled(t, new PasswordSprayDetector(t));
        addIfEnabled(t, new PathScanDetector(t));
        addIfEnabled(t, new OddHourDetector(t));
        addIfEnabled(t, new SqlInjectionDetector(t));
        addIfEnabled(t, new ScannerAgentDetector(t));
        addIfEnabled(t, new ZScoreDetector(t));
        addIfEnabled(t, threatIntel);
    }

    private void addIfEnabled(Thresholds t, LogDetector d) {
        if (t.enabled(d.ruleId())) {
            detectors.add(d);
        }
    }

    /** All findings this event causes, from every detector (dynamic dispatch on Detector.detect). */
    public synchronized List<Finding> process(LogEvent event) {
        List<Finding> found = new ArrayList<>();
        for (Detector<LogEvent> d : detectors) {
            found.addAll(d.detect(event));
        }
        return found;
    }

    /** Swaps the threat-intelligence lists after a feed update. */
    public synchronized void updateThreatIntel(CidrSet blocklist, CidrSet commandAndControl) {
        this.blocklist = blocklist;
        this.commandAndControl = commandAndControl;
        threatIntel.update(blocklist, commandAndControl);
    }

    public synchronized int detectorCount() {
        return detectors.size();
    }

    /**
     * The standard LineConsumer for live sources: parse with source, detect, publish to sink, and count.
     * A malformed line is counted and skipped (inner try), so one bad line never stops a tailer.
     */
    public LineConsumer consumerFor(LogSource source, FindingSink sink, SourceCounters counters) {
        return line -> {
            try {
                Optional<LogEvent> event = source.parse(line);
                if (event.isPresent()) {
                    counters.events.incrementAndGet();
                    for (Finding f : process(event.get())) {
                        sink.accept(f);
                        counters.findings.incrementAndGet();
                    }
                }
            } catch (MalformedLogException bad) {
                counters.malformed.incrementAndGet();
            }
        };
    }

    /** Reads a whole log file, sends every finding to sink, and counts good, bad and over-long lines. */
    public ReplayResult replay(Path file, LogSource source, FindingSink sink) throws IOException, InterruptedException {
        long lines = 0;
        long events = 0;
        long malformed = 0;
        long findings = 0;
        LineSplitter splitter = new LineSplitter(LogSource.MAX_LINE);
        InputStream in = Files.newInputStream(file);             // outer: the file
        try {
            byte[] buf = new byte[CHUNK];
            int n;
            boolean eof = false;
            while (!eof) {
                n = in.read(buf);
                List<String> batch = n > 0 ? splitter.feed(buf, n) : new ArrayList<>();
                if (n < 0) {
                    eof = true;
                    splitter.flush().ifPresent(batch::add);
                }
                for (String line : batch) {
                    lines++;
                    try {                                         // inner: one line; a bad line never stops the replay
                        Optional<LogEvent> event = source.parse(line);
                        if (event.isPresent()) {
                            events++;
                            for (Finding f : process(event.get())) {
                                sink.accept(f);
                                findings++;
                            }
                        }
                    } catch (MalformedLogException bad) {
                        malformed++;
                        LOG.fine("Skipping line " + lines + " of " + file.getFileName() + ": " + bad.getMessage());
                    }
                }
            }
        } finally {
            in.close();                                           // always, even after an exception
        }
        return new ReplayResult(lines, events, malformed, splitter.overlongLines(), findings);
    }
}
