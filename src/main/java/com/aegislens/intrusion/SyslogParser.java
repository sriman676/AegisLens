package com.aegislens.intrusion;

import com.aegislens.core.MalformedLogException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses syslog messages received over the network, RFC 3164 ("&lt;34&gt;Oct 11 22:14:15 host app[pid]: msg") and
 * RFC 5424 ("&lt;34&gt;1 2026-10-21T02:14:01Z host app pid msgid - msg"), and routes the message by app name:
 * sshd to SshLogSource, web servers to WebLogSource. Everything else is valid but not interesting.
 */
public class SyslogParser extends LogSource {

    private static final Pattern RFC5424 = Pattern.compile(
            "^<(\\d{1,3})>1 (\\S+) (\\S+) (\\S+) (\\S+) (\\S+) (-|(?:\\[[^\\]]*])+) ?(.*)$");
    private static final Pattern RFC3164 = Pattern.compile(
            "^<(\\d{1,3})>([A-Z][a-z]{2} [ \\d]\\d \\d{2}:\\d{2}:\\d{2}) (\\S+) ([^\\s\\[:]+)(?:\\[\\d+])?: ?(.*)$");
    private static final DateTimeFormatter LEGACY = DateTimeFormatter.ofPattern("MMM ppd HH:mm:ss yyyy", Locale.ENGLISH);
    private static final Set<String> WEB_APPS = Set.of("nginx", "apache", "apache2", "httpd");
    private static final int MAX_PRI = 191;

    private final SshLogSource ssh;
    private final WebLogSource web;
    private final Clock clock;
    private final ZoneId zone;

    public SyslogParser(SshLogSource ssh, WebLogSource web, Clock clock, ZoneId zone) {
        super("syslog");
        this.ssh = ssh;
        this.web = web;
        this.clock = clock;
        this.zone = zone;
    }

    /** One parsed syslog message before routing. */
    public record Message(int facility, int severity, Instant timestamp, String host, String app, String text) {
    }

    @Override
    public Optional<LogEvent> parse(String line) throws MalformedLogException {
        Message msg = parseMessage(line);
        if (msg.app().equals("sshd")) {
            return ssh.parseMessage(msg.timestamp(), msg.text(), line);
        }
        if (WEB_APPS.contains(msg.app())) {
            return web.parse(msg.text());
        }
        return Optional.empty();
    }

    /** Splits a syslog line into its header fields and message text. */
    public Message parseMessage(String line) throws MalformedLogException {
        String text = clean(line);
        Matcher m = RFC5424.matcher(text);
        if (m.matches()) {
            int pri = pri(m.group(1));
            String msg = m.group(8).startsWith("﻿") ? m.group(8).substring(1) : m.group(8);   // optional BOM
            return new Message(pri / 8, pri % 8, time5424(m.group(2)), m.group(3), m.group(4), msg);
        }
        m = RFC3164.matcher(text);
        if (m.matches()) {
            int pri = pri(m.group(1));
            return new Message(pri / 8, pri % 8, time3164(m.group(2)), m.group(3), m.group(4), m.group(5));
        }
        throw new MalformedLogException("not an RFC 3164 or 5424 syslog message: " + raw(text));
    }

    private static int pri(String text) throws MalformedLogException {
        int pri = Integer.parseInt(text);
        if (pri > MAX_PRI) {
            throw new MalformedLogException("syslog priority out of range: " + pri);
        }
        return pri;
    }

    private Instant time5424(String text) throws MalformedLogException {
        if (text.equals("-")) {
            return clock.instant();                 // NILVALUE: the sender had no clock
        }
        try {
            return OffsetDateTime.parse(text).toInstant();
        } catch (DateTimeParseException e) {
            throw new MalformedLogException("bad RFC 5424 time: " + text, e);
        }
    }

    /** RFC 3164 has no year or zone: use the receiver's zone and year (last year if that lies in the future). */
    private Instant time3164(String text) throws MalformedLogException {
        ZonedDateTime now = ZonedDateTime.now(clock.withZone(zone));
        try {
            LocalDateTime local = LocalDateTime.parse(text + " " + now.getYear(), LEGACY);
            ZonedDateTime candidate = local.atZone(zone);
            if (candidate.isAfter(now.plus(Duration.ofDays(1)))) {
                candidate = local.minusYears(1).atZone(zone);
            }
            return candidate.toInstant();
        } catch (DateTimeParseException e) {
            throw new MalformedLogException("bad RFC 3164 time: " + text, e);
        }
    }
}
