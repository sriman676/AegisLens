package com.aegislens.intrusion;

import java.time.Duration;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.Set;

/**
 * Every tunable number the detectors use, in one immutable record. The app builds it from the rule table
 * (so an analyst can change a threshold without a rebuild); defaults() holds the the README rule table values.
 * The intrusion package never reads the database itself.
 */
public record Thresholds(int bruteForceFailures, int sprayUsers, int pathScanPaths, double zScore,
                         Duration window, Duration escalation, LocalTime quietStart, LocalTime quietEnd, ZoneId zone,
                         String scannerAgentPattern, String injectionPattern, int maxTrackedIps, Set<String> disabledRules) {

    public static final int DEFAULT_BRUTE_FORCE = 5;
    public static final int DEFAULT_SPRAY_USERS = 5;
    public static final int DEFAULT_PATH_SCAN = 15;
    public static final double DEFAULT_Z = 3.0;
    public static final Duration DEFAULT_WINDOW = Duration.ofSeconds(60);
    public static final Duration DEFAULT_ESCALATION = Duration.ofMinutes(5);
    public static final LocalTime DEFAULT_QUIET_START = LocalTime.MIDNIGHT;
    public static final LocalTime DEFAULT_QUIET_END = LocalTime.of(5, 0);
    public static final String DEFAULT_SCANNER_AGENTS = "sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wpscan|hydra";
    /** SQL comment only after a quote or at the very end ("'--", "...1--"), so "/blog/2026--recap" is not an attack. */
    public static final String DEFAULT_INJECTION = "(?i)(union\\s+select|or\\s+1=1|'\\s?--|--\\s?$)";
    public static final int DEFAULT_MAX_TRACKED_IPS = 50_000;

    /** The the README rule table values, quiet hours in the given zone. */
    public static Thresholds defaults(ZoneId zone) {
        return new Thresholds(DEFAULT_BRUTE_FORCE, DEFAULT_SPRAY_USERS, DEFAULT_PATH_SCAN, DEFAULT_Z, DEFAULT_WINDOW,
                DEFAULT_ESCALATION, DEFAULT_QUIET_START, DEFAULT_QUIET_END, zone, DEFAULT_SCANNER_AGENTS,
                DEFAULT_INJECTION, DEFAULT_MAX_TRACKED_IPS, Set.of());
    }

    public boolean enabled(String ruleId) {
        return !disabledRules.contains(ruleId);
    }

    /** A copy with a smaller per-detector memory bound (used by tests). */
    public Thresholds withMaxTrackedIps(int max) {
        return new Thresholds(bruteForceFailures, sprayUsers, pathScanPaths, zScore, window, escalation, quietStart,
                quietEnd, zone, scannerAgentPattern, injectionPattern, max, disabledRules);
    }
}
