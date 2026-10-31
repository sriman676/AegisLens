package com.aegislens.intrusion;

import com.aegislens.core.MalformedLogException;
import com.aegislens.util.CidrSet;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses Apache/Nginx "combined" access-log lines:
 * IP - user [21/Oct/2026:09:30:01 +0530] "GET /path HTTP/1.1" 200 5120 "referer" "agent".
 * Handles escaped quotes, "-" sizes, IPv6, an optional virtual-host prefix, and an optional trailing quoted
 * X-Forwarded-For field. Behind a reverse proxy the first field is the proxy, so trustForwardedFor = true takes
 * the client from the first address in X-Forwarded-For instead.
 */
public class WebLogSource extends LogSource {

    private static final String QUOTED = "\"((?:[^\"\\\\]|\\\\.)*)\"";      // "..." with \" escapes, linear
    private static final Pattern COMBINED = Pattern.compile("^(?:(\\S+) )?(\\S+) (\\S+) (\\S+) \\[([^\\]]{1,40})] "
            + QUOTED + " (\\d{3}) (\\d+|-)(?: " + QUOTED + " " + QUOTED + ")?(?: " + QUOTED + ")?$");
    private static final Pattern REQUEST = Pattern.compile("^([A-Z]{1,16}) (\\S+)(?: \\S+)?$");
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    private final boolean trustForwardedFor;

    public WebLogSource(boolean trustForwardedFor) {
        super("web");
        this.trustForwardedFor = trustForwardedFor;
    }

    public WebLogSource() {
        this(false);
    }

    @Override
    public Optional<LogEvent> parse(String line) throws MalformedLogException {
        String text = clean(line);
        Matcher m = COMBINED.matcher(text);
        if (!m.matches()) {
            throw new MalformedLogException("not a combined access-log line: " + raw(text));
        }
        String ip = clientIp(m.group(2), m.group(11));
        String user = "-".equals(m.group(4)) ? null : m.group(4);
        Instant ts = time(m.group(5));
        String request = unescape(m.group(6));
        String method = null;
        String path = request;
        Matcher r = REQUEST.matcher(request);
        if (r.matches()) {
            method = r.group(1);
            path = r.group(2);
        }
        int status = Integer.parseInt(m.group(7));
        String agent = m.group(10) == null ? null : unescape(m.group(10));
        return Optional.of(LogEvent.web(ts, name, ip, user, method, path, status, agent, raw(text)));
    }

    private String clientIp(String firstField, String forwardedFor) throws MalformedLogException {
        if (trustForwardedFor && forwardedFor != null) {
            for (String candidate : forwardedFor.split(",")) {
                if (CidrSet.literal(candidate.trim()).isPresent()) {
                    return candidate.trim();
                }
            }
        }
        return requireIp(firstField);
    }

    private static Instant time(String text) throws MalformedLogException {
        try {
            return OffsetDateTime.parse(text, TIME).toInstant();
        } catch (DateTimeParseException e) {
            throw new MalformedLogException("bad access-log time: " + text, e);
        }
    }

    private static String unescape(String text) {
        return text.replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
