package com.aegislens.util;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The one definition of WEB-002 "injection pattern", shared by the web-log detector and the URL checker: the rule
 * table's SQL-injection pattern plus fixed XSS, path-traversal and Log4Shell patterns. Text is URL-decoded twice first,
 * because attackers double-encode. Every pattern is a plain alternation without nested quantifiers (no ReDoS).
 */
public final class InjectionPatterns {

    /** Longest text inspected; anything after it is ignored. */
    public static final int MAX_TEXT = 4096;

    /** Which kind matched and the matching text. */
    public record Hit(String kind, String match) {
    }

    private final Map<String, Pattern> patterns;

    /** sqlPattern is the WEB-002 pattern from the rule table (the README rule table). */
    public InjectionPatterns(String sqlPattern) {
        Map<String, Pattern> p = new LinkedHashMap<>();
        p.put("sql-injection", Pattern.compile("(?i)(" + sqlPattern
                + "|\\bsleep\\s?\\(|\\bbenchmark\\s?\\(|;\\s?drop\\s+table|'\\s?or\\s?'?\\w{1,20}'?\\s?=)"));   // ' or '1'='1
        p.put("xss", Pattern.compile("(?i)(<script|javascript:|onerror\\s?=|onload\\s?=)"));
        p.put("path-traversal", Pattern.compile("(\\.\\./|\\.\\.\\\\|%2e%2e%2f)", Pattern.CASE_INSENSITIVE));
        p.put("jndi-lookup", Pattern.compile("(?i)\\$\\{jndi:"));
        this.patterns = Collections.unmodifiableMap(p);
    }

    /** The first pattern that matches the (twice-decoded) text, if any. */
    public Optional<Hit> find(String text) {
        if (text == null) {
            return Optional.empty();
        }
        String t = decodeTwice(text.length() > MAX_TEXT ? text.substring(0, MAX_TEXT) : text);
        for (Map.Entry<String, Pattern> e : patterns.entrySet()) {
            Matcher m = e.getValue().matcher(t);
            if (m.find()) {
                return Optional.of(new Hit(e.getKey(), m.group()));
            }
        }
        return Optional.empty();
    }

    public static String decodeTwice(String text) {
        return decode(decode(text));
    }

    private static String decode(String text) {
        try {
            return URLDecoder.decode(text, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException badEscape) {
            return text;                         // a broken %-escape: look at the text as it is
        }
    }
}
