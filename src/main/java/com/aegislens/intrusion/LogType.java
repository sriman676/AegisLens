package com.aegislens.intrusion;

import java.time.Clock;
import java.time.ZoneId;

/**
 * The kinds of log AegisLens reads, each knowing how to make its parser. WINDOWS_XML is a file export, not a
 * line format, so it has no line parser (use WindowsEventXmlSource).
 */
public enum LogType {
    SSH("SSH (auth.log / secure)"),
    WEB("Web server access log"),
    SYSLOG("Syslog (RFC 3164 / 5424)"),
    WINDOWS_XML("Windows Security events (wevtutil XML)"),
    SYSMON_XML("Windows Sysmon events (wevtutil XML)");

    private final String label;

    LogType(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    /** A line parser for this type; the server zone is used for timestamps that carry no zone. */
    public LogSource newSource(Clock clock, ZoneId zone, boolean trustForwardedFor) {
        return switch (this) {
            case SSH -> new SshLogSource(clock, zone);
            case WEB -> new WebLogSource(trustForwardedFor);
            case SYSLOG -> new SyslogParser(new SshLogSource(clock, zone), new WebLogSource(trustForwardedFor), clock, zone);
            case WINDOWS_XML, SYSMON_XML -> throw new UnsupportedOperationException("Windows exports are files, not lines");
        };
    }

    @Override
    public String toString() {
        return label;
    }
}
