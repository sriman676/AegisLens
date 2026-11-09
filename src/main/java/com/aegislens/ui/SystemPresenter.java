package com.aegislens.ui;

import com.aegislens.app.AppConfig;
import com.aegislens.intel.FeedUpdater;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;
import java.util.Set;

/**
 * Logic of the Threat Intel and Settings views, kept out of JavaFX so it is unit-tested: feed state words, the
 * VirusTotal line (the key itself is never shown), allow-list clean-up, number checks for the form fields, and the
 * start-up options from aegislens.properties.
 */
public final class SystemPresenter {

    public static final int MIN_DAYS = 1;
    public static final int MAX_DAYS = 3650;
    /** Start-up options editable in Settings (all non-secret; keys never come from this file). */
    public static final List<String> STARTUP_KEYS = List.of("monitor.ssh.files", "monitor.web.files", "monitor.sysmon.folder",
            "monitor.silence.minutes", "syslog.bind", "syslog.udp.port", "syslog.tcp.port", "syslog.allow", "oddhour.start",
            "oddhour.end", "oddhour.zone", "dedupe.cooldown.minutes", "scan.threads", "feeds.enabled", "local.llm.url",
            "local.llm.model", "splitshield.url", "ai.redact.cloud", "ai.budget.hour", "ai.budget.day", "webhook.min.severity",
            "siem.host", "siem.port", "siem.protocol", "siem.format", "siem.min.severity", "siem.tls.cert.sha256", "siem.file");

    /** One start-up option: what aegislens.properties says (editable) and what is in effect now. */
    public record Option(String key, String inFile, String inEffect) {
    }

    private SystemPresenter() {
    }

    /** OFF, ERROR, STALE (older than 3 days) or OK, also used as a style word. */
    public static String feedState(FeedUpdater.Status s) {
        if (!s.enabled()) {
            return "OFF";
        }
        if (s.lastError() != null && !s.lastError().isBlank()) {
            return "ERROR";
        }
        return s.stale() || s.lastSuccess() == null ? "STALE" : "OK";
    }

    public static String feedAge(FeedUpdater.Status s, Instant now) {
        return s.lastSuccess() == null ? "never" : IntrusionPresenter.ago(s.lastSuccess(), now);
    }

    /** The VirusTotal line; it says whether a key is set, never what it is. */
    public static String virusTotalText(boolean enabled, int queued) {
        return enabled ? "VirusTotal: on (key from VT_API_KEY, hidden)  ·  " + queued + " lookups waiting"
                : "VirusTotal: off. Set the environment variable VT_API_KEY and restart to enable hash lookups.";
    }

    /** The SIEM status line; target is null when forwarding is off. */
    public static String siemText(String target, long sent, long failed, long dropped, String lastError) {
        if (target == null) {
            return "SIEM: off. Set siem.host (syslog, CEF or JSON) and/or siem.file (JSON lines) below, then Restart now.";
        }
        String line = "SIEM: " + target + "  ·  " + sent + " sent, " + failed + " failed, " + dropped + " dropped";
        return lastError == null ? line : line + "  ·  last error: " + lastError;
    }

    /** "10.0.0.0/8\n user:backup , 10.0.0.0/8" -> "10.0.0.0/8, user:backup" (commas or new lines, duplicates removed). */
    public static String normalizeAllowList(String text) {
        Set<String> entries = new LinkedHashSet<>();
        for (String raw : (text == null ? "" : text).split("[,\\r\\n]+")) {
            if (!raw.isBlank()) {
                entries.add(raw.strip());
            }
        }
        return String.join(", ", entries);
    }

    /** Retention days 1..3650, or empty if the text is not such a number. */
    public static OptionalInt days(String text) {
        try {
            int d = Integer.parseInt(text.strip());
            return d >= MIN_DAYS && d <= MAX_DAYS ? OptionalInt.of(d) : OptionalInt.empty();
        } catch (NumberFormatException | NullPointerException e) {
            return OptionalInt.empty();
        }
    }

    /** A rule threshold: a positive number, or empty. */
    public static OptionalDouble threshold(String text) {
        try {
            double d = Double.parseDouble(text.strip());
            return d > 0 && Double.isFinite(d) ? OptionalDouble.of(d) : OptionalDouble.empty();
        } catch (NumberFormatException | NullPointerException e) {
            return OptionalDouble.empty();
        }
    }

    /** Why the proxy fields cannot be saved, or empty. A blank host means "no fixed proxy". */
    public static Optional<String> proxyProblem(String host, String port) {
        if (host == null || host.isBlank()) {
            return Optional.empty();
        }
        if (!host.strip().matches("[A-Za-z0-9.:\\-\\[\\]]+")) {
            return Optional.of("The proxy host may only contain letters, digits, '.', '-' and ':'.");
        }
        try {
            int p = Integer.parseInt(port.strip());
            return p >= 1 && p <= 65535 ? Optional.empty() : Optional.of("The proxy port must be 1 to 65535.");
        } catch (NumberFormatException | NullPointerException e) {
            return Optional.of("The proxy port must be a number.");
        }
    }

    /**
     * Every start-up option with its value in the file (blank = default) and in effect now ("(default)" when not set;
     * a command-line or AEGISLENS_* value wins over the file, so the two can differ).
     */
    public static List<Option> startupOptions(AppConfig config, Map<String, String> inFile) {
        List<Option> list = new ArrayList<>();
        for (String key : STARTUP_KEYS) {
            String value = config.get(key, null);
            list.add(new Option(key, inFile.getOrDefault(key, ""), value == null || value.isBlank() ? "(default)" : value));
        }
        return list;
    }

    /** IOC counts as "IP 1 757  ·  CIDR 1 756  ·  HASH 1" (largest first). */
    public static String iocLine(Map<String, Integer> byKind) {
        if (byKind.isEmpty()) {
            return "No indicators stored yet: press Update now.";
        }
        List<String> parts = new ArrayList<>();
        byKind.entrySet().stream().sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .forEach(e -> parts.add(e.getKey() + " " + e.getValue()));
        return "Indicators stored: " + String.join("  ·  ", parts);
    }
}
