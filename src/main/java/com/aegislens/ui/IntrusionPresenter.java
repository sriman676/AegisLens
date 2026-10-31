package com.aegislens.ui;

import com.aegislens.core.Finding;
import com.aegislens.intrusion.LogType;
import com.aegislens.intrusion.MonitorManager;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Logic of the Intrusion view, kept out of JavaFX so it is unit-tested: guesses the log type from a file name, checks
 * the form before Start, and turns monitor counters and findings into the short text the view shows.
 */
public final class IntrusionPresenter {

    /** Findings kept in the "recent" list. */
    public static final int RECENT = 100;
    /** Types that can be tailed live; the others only replay. */
    public static final List<LogType> LIVE_TYPES = List.of(LogType.SSH, LogType.WEB);

    private IntrusionPresenter() {
    }

    /** auth.log -> SSH, access.log -> WEB, sysmon*.xml -> Sysmon, other *.xml -> Windows Security, syslog -> SYSLOG. */
    public static LogType guessType(String fileName) {
        String n = fileName.toLowerCase(Locale.ROOT);
        if (n.endsWith(".xml")) {
            return n.contains("sysmon") ? LogType.SYSMON_XML : LogType.WINDOWS_XML;
        }
        if (n.contains("access")) {
            return LogType.WEB;
        }
        return n.contains("syslog") || n.contains("messages") ? LogType.SYSLOG : LogType.SSH;
    }

    /** Why Start cannot run yet, or empty if the form is fine. */
    public static Optional<String> problem(String path, LogType type, boolean live) {
        if (path == null || path.isBlank()) {
            return Optional.of("Choose a log file first (Browse...).");
        }
        if (type == null) {
            return Optional.of("Choose the kind of log.");
        }
        if (live && !LIVE_TYPES.contains(type)) {
            return Optional.of(type.label() + " cannot be watched live; use Replay (or the syslog listener in Settings).");
        }
        return Optional.empty();
    }

    /** "12 s ago", "3 min ago", "never" for the last-activity column. */
    public static String ago(Instant last, Instant now) {
        if (last == null || last.equals(Instant.EPOCH)) {
            return "never";
        }
        long s = Math.max(0, Duration.between(last, now).toSeconds());
        return s < 60 ? s + " s ago" : s < 3600 ? s / 60 + " min ago" : s / 3600 + " h ago";
    }

    /** "3 sources · 1 204 lines · 18 findings" under the table. */
    public static String summary(List<MonitorManager.SourceStatus> sources) {
        long lines = sources.stream().mapToLong(MonitorManager.SourceStatus::lines).sum();
        long found = sources.stream().mapToLong(MonitorManager.SourceStatus::findings).sum();
        return sources.size() + (sources.size() == 1 ? " source" : " sources") + "  ·  " + lines + " lines  ·  " + found
                + " findings";
    }

    /** True if a finding passes the filter box (rule, target or description contains the text, any case). */
    public static boolean matches(Finding f, String filter) {
        if (filter == null || filter.isBlank()) {
            return true;
        }
        String needle = filter.strip().toLowerCase(Locale.ROOT);
        return (f.ruleId() + " " + f.target() + " " + f.description()).toLowerCase(Locale.ROOT).contains(needle);
    }

    /** True for findings from the log detectors (NET-, WEB-, MON- rules), which this view lists. */
    public static boolean isIntrusion(Finding f) {
        return f.ruleId().startsWith("NET-") || f.ruleId().startsWith("WEB-") || f.ruleId().startsWith("MON-");
    }
}
