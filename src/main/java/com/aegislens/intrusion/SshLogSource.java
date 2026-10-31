package com.aegislens.intrusion;

import com.aegislens.core.MalformedLogException;
import com.aegislens.intrusion.LogEvent.Action;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses sshd lines from /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL), in both timestamp styles:
 * traditional "Oct 21 02:14:01" (no year: inferred from the clock, going back a year if the date would be more than a
 * day in the future, which handles the December/January rollover) and RFC 3339 "2026-10-21T02:14:01.123+05:30".
 * Lines from other programs are valid but not interesting (empty result). All patterns are linear (no ReDoS).
 */
public class SshLogSource extends LogSource {

    private static final List<String> MONTHS = List.of("Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec");
    private static final Pattern TRADITIONAL = Pattern.compile(
            "^([A-Z][a-z]{2}) {1,2}(\\d{1,2}) (\\d{2}):(\\d{2}):(\\d{2}) (\\S+) ([^\\s\\[:]+)(?:\\[\\d+])?: (.*)$");
    private static final Pattern RFC3339 = Pattern.compile(
            "^(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?(?:Z|[+-]\\d{2}:\\d{2})) (\\S+) ([^\\s\\[:]+)(?:\\[\\d+])?: (.*)$");

    private static final Pattern FAILED = Pattern.compile(
            "^Failed (?:password|publickey|none|keyboard-interactive/pam) for (invalid user )?(\\S*) from (\\S+) port \\d+");
    private static final Pattern INVALID = Pattern.compile("^Invalid user (\\S*) from (\\S+)");
    private static final Pattern ACCEPTED = Pattern.compile(
            "^Accepted (?:password|publickey|keyboard-interactive/pam|gssapi-with-mic) for (\\S+) from (\\S+) port \\d+");
    private static final Pattern CLOSED = Pattern.compile("^Connection closed by authenticating user (\\S+) (\\S+) port \\d+");
    private static final Pattern MAX_AUTH = Pattern.compile(
            "^(?:error: )?maximum authentication attempts exceeded for (invalid user )?(\\S*) from (\\S+) port \\d+");
    private static final Pattern DISCONNECTED_INVALID = Pattern.compile("^Disconnected from invalid user (\\S*) (\\S+) port \\d+");

    private final Clock clock;
    private final ZoneId zone;

    /** zone is the server's time zone, used for traditional timestamps that carry none. */
    public SshLogSource(Clock clock, ZoneId zone) {
        super("ssh");
        this.clock = clock;
        this.zone = zone;
    }

    public SshLogSource() {
        this(Clock.systemDefaultZone(), ZoneId.systemDefault());
    }

    @Override
    public Optional<LogEvent> parse(String line) throws MalformedLogException {
        String text = clean(line);
        Matcher m = TRADITIONAL.matcher(text);
        if (m.matches()) {
            Instant ts = traditionalTime(m.group(1), m.group(2), m.group(3), m.group(4), m.group(5));
            return isSshd(m.group(7)) ? parseMessage(ts, m.group(8), text) : Optional.empty();
        }
        m = RFC3339.matcher(text);
        if (m.matches()) {
            Instant ts;
            try {
                ts = OffsetDateTime.parse(m.group(1)).toInstant();
            } catch (DateTimeParseException e) {
                throw new MalformedLogException("bad timestamp: " + m.group(1), e);
            }
            return isSshd(m.group(3)) ? parseMessage(ts, m.group(4), text) : Optional.empty();
        }
        throw new MalformedLogException("not a syslog-style line: " + raw(text));
    }

    /** Parses only the sshd message part (also used by SyslogParser, which has already read the timestamp). */
    public Optional<LogEvent> parseMessage(Instant ts, String message, String line) throws MalformedLogException {
        String rawLine = raw(line);
        Matcher m;
        if ((m = FAILED.matcher(message)).find()) {
            String detail = m.group(1) != null ? "invalid user" : null;
            return Optional.of(LogEvent.login(ts, name, requireIp(m.group(3)), m.group(2), Action.FAILED_LOGIN, detail, rawLine));
        }
        if ((m = ACCEPTED.matcher(message)).find()) {
            return Optional.of(LogEvent.login(ts, name, requireIp(m.group(2)), m.group(1), Action.SUCCESS_LOGIN, null, rawLine));
        }
        if ((m = INVALID.matcher(message)).find()) {
            return Optional.of(LogEvent.login(ts, name, requireIp(m.group(2)), m.group(1), Action.INVALID_USER, null, rawLine));
        }
        if ((m = MAX_AUTH.matcher(message)).find()) {
            return Optional.of(LogEvent.login(ts, name, requireIp(m.group(3)), m.group(2), Action.MAX_AUTH, null, rawLine));
        }
        if ((m = CLOSED.matcher(message)).find()) {
            return Optional.of(LogEvent.login(ts, name, requireIp(m.group(2)), m.group(1), Action.DISCONNECT, null, rawLine));
        }
        if ((m = DISCONNECTED_INVALID.matcher(message)).find()) {
            return Optional.of(LogEvent.login(ts, name, requireIp(m.group(2)), m.group(1), Action.DISCONNECT, "invalid user", rawLine));
        }
        return Optional.empty();                    // other sshd chatter (session opened, key exchange, ...)
    }

    private static boolean isSshd(String program) {
        return program.equals("sshd") || program.startsWith("sshd-");
    }

    /** "Oct 21 02:14:01" in the server zone, in the clock's year, or last year if that would be in the future. */
    private Instant traditionalTime(String mon, String day, String h, String min, String s) throws MalformedLogException {
        int month = MONTHS.indexOf(mon) + 1;
        if (month == 0) {
            throw new MalformedLogException("unknown month: " + mon);
        }
        ZonedDateTime now = ZonedDateTime.now(clock.withZone(zone));
        try {
            LocalDateTime local = LocalDateTime.of(now.getYear(), month, Integer.parseInt(day),
                    Integer.parseInt(h), Integer.parseInt(min), Integer.parseInt(s));
            ZonedDateTime candidate = local.atZone(zone);
            if (candidate.isAfter(now.plus(Duration.ofDays(1)))) {
                candidate = local.minusYears(1).atZone(zone);     // a December line read in January
            }
            return candidate.toInstant();
        } catch (java.time.DateTimeException e) {
            throw new MalformedLogException("bad date: " + mon + " " + day, e);
        }
    }
}
