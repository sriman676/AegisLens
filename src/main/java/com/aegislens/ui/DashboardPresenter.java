package com.aegislens.ui;

import com.aegislens.app.ScanCoordinator;
import com.aegislens.core.Finding;
import com.aegislens.core.Severity;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.FindingRepository.TargetCount;
import com.aegislens.db.RetentionJob;
import com.aegislens.intel.FeedUpdater;
import com.aegislens.intrusion.MonitorManager.SourceStatus;

import java.sql.SQLException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Collects everything the dashboard shows into one immutable Snapshot (counts per severity and module, top attackers,
 * recent findings, findings per hour for the last 24 h, database size, AI providers, live sources) and formats it as text. Plain Java with no JavaFX,
 * so it is unit-tested; DashboardView only draws what this returns. Runs on a background thread, never the FX thread.
 */
public final class DashboardPresenter {

    public static final int TOP_ATTACKERS = 5;
    public static final int RECENT = 50;
    /** Hours shown on the timeline and in the card sparklines. */
    public static final int HOURS = 24;
    private static final DateTimeFormatter HOUR_LABEL = DateTimeFormatter.ofPattern("HH:00");

    /** One consistent picture of the data at takenAt. */
    public record Snapshot(Map<Severity, Integer> bySeverity, Map<String, Integer> byModule, List<TargetCount> topTargets,
                           List<Finding> recent, long dbBytes, List<String> providers, List<SourceStatus> sources,
                           Map<Severity, int[]> hourly, Instant takenAt) {

        public int total() {
            int sum = 0;
            for (int n : bySeverity.values()) {
                sum += n;
            }
            return sum;
        }

        public long runningSources() {
            return sources.stream().filter(s -> !s.state().equals("TERMINATED") && !s.state().equals("NEW")).count();
        }
    }

    private final FindingRepository findings;
    private final RetentionJob sizes;
    private final Supplier<List<String>> providers;
    private final Supplier<List<SourceStatus>> sources;
    private final Supplier<List<FeedUpdater.Status>> feeds;

    public DashboardPresenter(ScanCoordinator coordinator) {
        this(coordinator.database(), coordinator.explanations()::providerNames, coordinator::monitorStatus, coordinator::feedStatus);
    }

    DashboardPresenter(Database db, Supplier<List<String>> providers, Supplier<List<SourceStatus>> sources) {
        this(db, providers, sources, List::of);
    }

    DashboardPresenter(Database db, Supplier<List<String>> providers, Supplier<List<SourceStatus>> sources,
                       Supplier<List<FeedUpdater.Status>> feeds) {
        this.findings = new FindingRepository(db);
        this.sizes = new RetentionJob(db);
        this.providers = providers;
        this.sources = sources;
        this.feeds = feeds;
    }

    public Snapshot snapshot() throws SQLException {
        Instant now = Instant.now();
        return new Snapshot(findings.countBySeverity(), findings.countByModule(), findings.topTargets(TOP_ATTACKERS),
                findings.findRecent(RECENT), sizes.sizeBytes(), List.copyOf(providers.get()), List.copyOf(sources.get()),
                hourly(now), now);
    }

    /** Per severity, HOURS counts (oldest first) for the hours ending with the current one. */
    Map<Severity, int[]> hourly(Instant now) throws SQLException {
        Instant currentHour = now.truncatedTo(ChronoUnit.HOURS);
        Instant start = currentHour.minus(HOURS - 1, ChronoUnit.HOURS);
        Map<Severity, int[]> result = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            result.put(s, new int[HOURS]);
        }
        for (FindingRepository.HourCount h : findings.countByHourSince(start)) {
            long index = ChronoUnit.HOURS.between(start, Instant.parse(h.hour() + ":00:00Z"));
            if (index >= 0 && index < HOURS) {
                result.get(h.severity())[(int) index] += h.count();
            }
        }
        return result;
    }

    /** Local-time labels ("14:00") for the HOURS buckets of the snapshot taken at takenAt. */
    public static List<String> hourLabels(Instant takenAt, ZoneId zone) {
        Instant start = takenAt.truncatedTo(ChronoUnit.HOURS).minus(HOURS - 1, ChronoUnit.HOURS);
        List<String> labels = new ArrayList<>();
        for (int i = 0; i < HOURS; i++) {
            labels.add(HOUR_LABEL.format(start.plus(i, ChronoUnit.HOURS).atZone(zone)));
        }
        return labels;
    }

    /** "203.0.113.45   ·  12 findings" for the top-attackers list. */
    public static String attackerLine(TargetCount t) {
        return t.target() + "   ·  " + t.count() + (t.count() == 1 ? " finding" : " findings");
    }

    /**
     * What a screen reader says for a chart (charts are not only colours): "Findings by module: Intrusion 6,
     * Malware 4" or "...: none". Works for any number type (wildcard).
     */
    public static String spoken(String title, Map<String, ? extends Number> parts) {
        List<String> said = new ArrayList<>();
        parts.forEach((name, n) -> said.add(name.charAt(0) + name.substring(1).toLowerCase(Locale.ROOT) + " " + n));
        return title + ": " + (said.isEmpty() ? "none" : String.join(", ", said));
    }

    /** 1536 -> "1.5 KB". */
    public static String humanBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        String[] units = {"KB", "MB", "GB", "TB"};
        double value = bytes;
        int unit = -1;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024;
            unit++;
        }
        return String.format(Locale.ROOT, "%.1f %s", value, units[unit]);
    }

    /** Text for the status bar items, in order: database, AI, monitors. */
    public static List<String> statusItems(Snapshot s) {
        String ai = s.providers().size() <= 1 ? "AI: offline templates" : "AI: " + String.join(", ", s.providers());
        String monitors = s.sources().isEmpty() ? "Live monitors: none configured"
                : "Live monitors: " + s.runningSources() + " of " + s.sources().size() + " running";
        return List.of("Database " + humanBytes(s.dbBytes()), ai, monitors, s.total() + " active findings");
    }

    /** The threat-feed part of the status bar (read on the refresh thread). */
    public String feedLine() {
        return feedText(feeds.get());
    }

    /** "Threat feeds: 2 fresh", "Threat feeds: 1 of 2 stale (last update 2026-10-27)" or "Threat feeds: off". */
    public static String feedText(List<FeedUpdater.Status> list) {
        List<FeedUpdater.Status> on = list.stream().filter(FeedUpdater.Status::enabled).toList();
        if (on.isEmpty()) {
            return "Threat feeds: off";
        }
        long stale = on.stream().filter(FeedUpdater.Status::stale).count();
        if (stale == 0) {
            return "Threat feeds: " + on.size() + " fresh";
        }
        String last = on.stream().map(FeedUpdater.Status::lastSuccess).filter(java.util.Objects::nonNull).max(Instant::compareTo)
                .map(t -> " (last update " + t.toString().substring(0, 10) + ")").orElse(" (never updated)");
        return "Threat feeds: " + stale + " of " + on.size() + " stale" + last;
    }
}
