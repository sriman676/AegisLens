package com.aegislens.app;

import com.aegislens.db.IocRepository;
import com.aegislens.db.RuleDef;
import com.aegislens.db.RuleRepository;
import com.aegislens.intrusion.MonitorManager;
import com.aegislens.intrusion.Thresholds;
import com.aegislens.util.CidrSet;

import java.nio.file.Path;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Builds what the intrusion package needs from the database and config, so intrusion itself never touches either:
 * detector Thresholds from the rule table (analyst-editable) and the threat-intelligence CidrSets from the ioc table.
 */
public final class IntrusionSetup {

    public static final String QUIET_START = "oddhour.start";
    public static final String QUIET_END = "oddhour.end";
    public static final String ZONE = "oddhour.zone";
    public static final String SSH_FILES = "monitor.ssh.files";
    public static final String WEB_FILES = "monitor.web.files";
    public static final String START_AT_BEGINNING = "monitor.start.at.beginning";
    public static final String SILENCE_MINUTES = "monitor.silence.minutes";
    public static final String SYSLOG_BIND = "syslog.bind";
    public static final String SYSLOG_UDP = "syslog.udp.port";
    public static final String SYSLOG_TCP = "syslog.tcp.port";
    public static final String SYSLOG_ALLOW = "syslog.allow";
    public static final String SYSLOG_RATE = "syslog.rate";
    public static final int DEFAULT_SYSLOG_RATE = 200;
    public static final int DEFAULT_SILENCE_MINUTES = 60;

    private static final Logger LOG = Logger.getLogger(IntrusionSetup.class.getName());

    private IntrusionSetup() {
    }

    /** the README rule table defaults, overridden by thresholds/patterns from the rule table and quiet hours from config. */
    public static Thresholds thresholds(RuleRepository rules, AppConfig config) throws SQLException {
        Thresholds d = Thresholds.defaults(zone(config));
        Set<String> disabled = new HashSet<>();
        int brute = d.bruteForceFailures();
        int spray = d.sprayUsers();
        int paths = d.pathScanPaths();
        double z = d.zScore();
        String agents = d.scannerAgentPattern();
        String injection = d.injectionPattern();
        for (RuleDef r : rules.findAll()) {
            if (!r.enabled()) {
                disabled.add(r.id());
            }
            switch (r.id()) {
                case "NET-001" -> brute = intOr(r.threshold(), brute);
                case "NET-002" -> paths = intOr(r.threshold(), paths);
                case "NET-004" -> z = r.threshold() == null ? z : r.threshold();
                case "NET-006" -> agents = r.pattern() == null ? agents : r.pattern();
                case "NET-007" -> spray = intOr(r.threshold(), spray);
                case "WEB-002" -> injection = r.pattern() == null ? injection : r.pattern();
                default -> { }
            }
        }
        return new Thresholds(brute, spray, paths, z, d.window(), d.escalation(),
                time(config, QUIET_START, d.quietStart()), time(config, QUIET_END, d.quietEnd()), d.zone(),
                agents, injection, d.maxTrackedIps(), disabled);
    }

    /** IP and CIDR indicators split into [0] general blocklist and [1] command-and-control (source names c2 or feodo). */
    public static CidrSet[] threatIntel(IocRepository iocs) throws SQLException {
        CidrSet block = new CidrSet();
        CidrSet c2 = new CidrSet();
        for (String kind : new String[] {"IP", "CIDR"}) {
            for (Map.Entry<String, String> e : iocs.valuesBySource(kind).entrySet()) {
                String source = e.getValue().toLowerCase(Locale.ROOT);
                boolean isC2 = source.contains("c2") || source.contains("feodo");
                (isC2 ? c2 : block).add(e.getKey());
            }
        }
        return new CidrSet[] {block, c2};
    }

    /**
     * Live monitoring from config: monitor.ssh.files / monitor.web.files (comma-separated paths), syslog.bind,
     * syslog.udp.port / syslog.tcp.port (-1 = off), syslog.allow, syslog.rate, monitor.silence.minutes (0 = off).
     */
    public static MonitorManager.Config monitorConfig(AppConfig config) {
        return new MonitorManager.Config(paths(config.get(SSH_FILES, "")), paths(config.get(WEB_FILES, "")),
                Boolean.parseBoolean(config.get(START_AT_BEGINNING, "false")), config.get(SYSLOG_BIND, "127.0.0.1"),
                config.getInt(SYSLOG_UDP, -1), config.getInt(SYSLOG_TCP, -1), config.get(SYSLOG_ALLOW, "127.0.0.1,::1"),
                config.getInt(SYSLOG_RATE, DEFAULT_SYSLOG_RATE), config.getMinutes(SILENCE_MINUTES, DEFAULT_SILENCE_MINUTES),
                zone(config));
    }

    private static List<Path> paths(String csv) {
        List<Path> list = new ArrayList<>();
        for (String part : csv.split(",")) {
            if (!part.isBlank()) {
                list.add(Path.of(part.trim()));
            }
        }
        return list;
    }

    private static int intOr(Double value, int fallback) {
        return value == null ? fallback : (int) Math.round(value);
    }

    /** The server time zone (oddhour.zone, else the system zone): for log timestamps without a zone and quiet hours. */
    static ZoneId zone(AppConfig config) {
        String text = config.get(ZONE, null);
        try {
            return text == null ? ZoneId.systemDefault() : ZoneId.of(text);
        } catch (java.time.DateTimeException e) {
            LOG.warning("Unknown time zone '" + text + "', using the system zone");
            return ZoneId.systemDefault();
        }
    }

    private static LocalTime time(AppConfig config, String key, LocalTime fallback) {
        String text = config.get(key, null);
        try {
            return text == null ? fallback : LocalTime.parse(text);
        } catch (DateTimeParseException e) {
            LOG.warning("Setting " + key + " is not a time like 05:00, using " + fallback);
            return fallback;
        }
    }
}
