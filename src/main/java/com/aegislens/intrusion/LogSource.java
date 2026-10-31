package com.aegislens.intrusion;

import com.aegislens.core.MalformedLogException;
import com.aegislens.util.CidrSet;

import java.util.Optional;

/**
 * Parent of every line-based log parser (SSH, web, syslog). Log text is untrusted, so every subclass goes through
 * clean(): length cap, control characters removed. parse() returns empty for valid lines that carry nothing of
 * interest (for example a CRON line in auth.log) and throws MalformedLogException for lines it cannot understand;
 * the caller counts and skips those.
 */
public abstract class LogSource {

    /** Longest line accepted; longer ones are rejected. */
    public static final int MAX_LINE = 8192;
    /** How much of the original line is kept as evidence. */
    public static final int RAW_CAP = 512;

    protected final String name;

    protected LogSource(String name) {
        this.name = name;
    }

    public final String name() {
        return name;
    }

    /** Parses one line. Empty = understood but not interesting. */
    public abstract Optional<LogEvent> parse(String line) throws MalformedLogException;

    /** Rejects null, blank and over-long lines and replaces control characters (except tab) with spaces. */
    protected static String clean(String line) throws MalformedLogException {
        if (line == null || line.isBlank()) {
            throw new MalformedLogException("empty line");
        }
        if (line.length() > MAX_LINE) {
            throw new MalformedLogException("line longer than " + MAX_LINE + " characters");
        }
        StringBuilder sb = new StringBuilder(line.length());
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            sb.append(Character.isISOControl(ch) && ch != '\t' ? ' ' : ch);
        }
        return sb.toString().strip();
    }

    /** The first RAW_CAP characters, for evidence. */
    protected static String raw(String line) {
        return line.length() <= RAW_CAP ? line : line.substring(0, RAW_CAP);
    }

    /** The text if it is an IP literal (IPv4 or IPv6), otherwise a MalformedLogException. */
    protected static String requireIp(String text) throws MalformedLogException {
        if (CidrSet.literal(text).isEmpty()) {
            throw new MalformedLogException("not an IP address: " + raw(text));
        }
        return text;
    }
}
