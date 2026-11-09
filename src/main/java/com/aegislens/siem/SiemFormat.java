package com.aegislens.siem;

import com.aegislens.core.Finding;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * How a finding looks to a SIEM. Two payloads that every common SIEM ingests:
 * <ul>
 *   <li>CEF (ArcSight Common Event Format): Splunk, QRadar, Microsoft Sentinel (CEF via AMA), ArcSight, Elastic, Wazuh,
 *       Graylog;</li>
 *   <li>JSON with Elastic Common Schema field names (@timestamp, event.*, rule.id, source.ip, ...): Elastic, Splunk,
 *       Wazuh, Graylog, OpenSearch.</li>
 * </ul>
 * Over syslog the payload follows an RFC 5424 header. Raw log lines (evidence "line") are never sent, like the webhook;
 * control characters are removed so one finding is always one line.
 */
public final class SiemFormat {

    public static final String VENDOR = "AegisLens";
    /** Syslog facility 10 (authpriv: security messages). */
    static final int FACILITY = 10;
    static final int MAX_FIELD = 1000;
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern IPV4 = Pattern.compile("(25[0-5]|2[0-4]\\d|1?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}");
    private static final Pattern IPV6 = Pattern.compile("[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*");

    private SiemFormat() {
    }

    /** CEF:0|AegisLens|AegisLens|1.0.0|NET-001|5 failed SSH logins ...|7|rt=... src=... */
    public static String cef(Finding f, String version) {
        StringBuilder s = new StringBuilder("CEF:0|").append(VENDOR).append('|').append(VENDOR).append('|')
                .append(header(version)).append('|').append(header(f.ruleId())).append('|')
                .append(header(cap(f.description()))).append('|').append(cefSeverity(f.score())).append('|');
        s.append("rt=").append(f.timestamp().toEpochMilli());
        if (isIp(f.target())) {
            s.append(" src=").append(f.target());
        }
        s.append(" cat=").append(f.severity());
        s.append(" msg=").append(ext(cap(f.description())));
        s.append(" cn1Label=score cn1=").append(f.score());
        s.append(" cs1Label=module cs1=").append(ext(f.source()));
        s.append(" cs2Label=target cs2=").append(ext(cap(f.target())));
        s.append(" cs3Label=status cs3=").append(ext(f.status()));
        String evidence = evidenceText(f);
        if (!evidence.isEmpty()) {
            s.append(" cs4Label=evidence cs4=").append(ext(cap(evidence)));
        }
        if (f.id() > 0) {
            s.append(" externalId=").append(f.id());
        }
        return s.toString();
    }

    /** One JSON object on one line, with Elastic Common Schema names. */
    public static String json(Finding f, String version, String hostname) {
        ObjectNode root = JSON.createObjectNode();
        root.put("@timestamp", f.timestamp().truncatedTo(ChronoUnit.MILLIS).toString());
        root.put("message", clean(cap(f.description())));
        ObjectNode event = root.putObject("event");
        event.put("kind", "alert");
        event.put("module", "aegislens");
        event.put("dataset", "aegislens.finding");
        event.put("severity", f.score());
        event.put("risk_score", f.score());
        if (f.id() > 0) {
            event.put("id", String.valueOf(f.id()));
        }
        root.putObject("rule").put("id", f.ruleId());
        if (isIp(f.target())) {
            root.putObject("source").put("ip", f.target());
        }
        ObjectNode observer = root.putObject("observer");
        observer.put("vendor", VENDOR);
        observer.put("product", VENDOR);
        observer.put("version", version);
        observer.put("hostname", hostname);
        ObjectNode own = root.putObject("aegislens");
        own.put("severity", f.severity().name());
        own.put("score", f.score());
        own.put("module", f.source());
        own.put("target", clean(cap(f.target())));
        own.put("status", f.status());
        ObjectNode evidence = own.putObject("evidence");
        for (Map.Entry<String, String> e : f.evidence().entrySet()) {
            if (!e.getKey().equals("line")) {
                evidence.put(e.getKey(), clean(cap(e.getValue())));
            }
        }
        try {
            return JSON.writeValueAsString(root);
        } catch (IOException e) {
            throw new IllegalStateException("a tree of strings and numbers is always serialisable", e);
        }
    }

    /** RFC 5424: "<PRI>1 TIMESTAMP HOST aegislens - FINDING - payload". */
    public static String syslog(Finding f, String hostname, String payload, Instant now) {
        int pri = FACILITY * 8 + syslogSeverity(f.score());
        return "<" + pri + ">1 " + DateTimeFormatter.ISO_INSTANT.format(now.truncatedTo(ChronoUnit.MILLIS)) + ' '
                + headerToken(hostname) + " aegislens - FINDING - " + payload;
    }

    /** 0-100 score to CEF's 0-10. */
    static int cefSeverity(int score) {
        return Math.round(score / 10f);
    }

    /** CRITICAL 2 (crit), HIGH 3 (err), MEDIUM 4 (warning), LOW 5 (notice). */
    static int syslogSeverity(int score) {
        return switch (com.aegislens.core.Severity.fromScore(score)) {
            case CRITICAL -> 2;
            case HIGH -> 3;
            case MEDIUM -> 4;
            case LOW -> 5;
        };
    }

    /** A literal IPv4 or IPv6 address (never a DNS lookup). */
    static boolean isIp(String s) {
        return IPV4.matcher(s).matches() || (s.indexOf(':') >= 0 && IPV6.matcher(s).matches() && s.length() <= 45);
    }

    /** CEF header fields escape \ and |. */
    static String header(String s) {
        return clean(s).replace("\\", "\\\\").replace("|", "\\|");
    }

    /** CEF extension values escape \ and = (new lines are already gone). */
    static String ext(String s) {
        return clean(s).replace("\\", "\\\\").replace("=", "\\=");
    }

    private static String evidenceText(Finding f) {
        StringBuilder s = new StringBuilder();
        for (Map.Entry<String, String> e : f.evidence().entrySet()) {
            if (!e.getKey().equals("line")) {
                s.append(s.isEmpty() ? "" : "; ").append(e.getKey()).append(": ").append(e.getValue());
            }
        }
        return s.toString();
    }

    private static String clean(String s) {
        return s.replaceAll("\\p{Cntrl}", " ");
    }

    private static String cap(String s) {
        return s.length() <= MAX_FIELD ? s : s.substring(0, MAX_FIELD - 1) + "…";
    }

    /** RFC 5424 header tokens are printable ASCII without spaces; "-" when nothing is left. */
    static String headerToken(String s) {
        String t = s == null ? "" : s.replaceAll("[^\\x21-\\x7e]", "");
        return t.isEmpty() ? "-" : t.substring(0, Math.min(255, t.length())).toLowerCase(Locale.ROOT);
    }
}
