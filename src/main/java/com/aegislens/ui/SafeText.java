package com.aegislens.ui;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.regex.Pattern;

/**
 * Makes untrusted text (log lines, file names, URLs, AI answers) safe to show: control characters become spaces,
 * Unicode direction overrides are removed (U+202E can make "exe.gpj" display as "jpg.exe"), and long text is cut so a
 * huge value cannot freeze a table. Shown only in Label, Text, TextArea or table cells, never in a WebView (G10).
 */
public final class SafeText {

    /** Longest text shown in one cell or label. */
    public static final int MAX_TEXT = 300;
    /** Bidi embedding/override/isolate marks and the invisible direction marks. */
    private static final Pattern BIDI = Pattern.compile("[\\u202A-\\u202E\\u2066-\\u2069\\u200E\\u200F\\u061C]");
    private static final Pattern CONTROL = Pattern.compile("\\p{Cntrl}");
    private static final DateTimeFormatter CLOCK = DateTimeFormatter.ofPattern("MM-dd HH:mm:ss");

    private SafeText() {
    }

    /** A file path becomes its file name (C:\Users\x\tool.elf -> tool.elf); IPs, URLs and names stay as they are. */
    public static String target(String text) {
        String t = shorten(text);
        if (t.contains("://") || !(t.contains("/") || t.contains("\\"))) {
            return t;
        }
        String name = t.substring(Math.max(t.lastIndexOf('/'), t.lastIndexOf('\\')) + 1);
        return name.isEmpty() ? t : name;
    }

    /** A stored UTC time ("2026-10-30T15:07:28Z") in this computer's time zone, like the dashboard: "10-30 20:37:28". */
    public static String time(String iso) {
        return time(iso, ZoneId.systemDefault());
    }

    /** The same in a given zone; anything that is not an ISO instant is shown as it is. */
    static String time(String iso, ZoneId zone) {
        try {
            return CLOCK.withZone(zone).format(Instant.parse(iso));
        } catch (DateTimeParseException | NullPointerException e) {
            return shorten(iso);
        }
    }

    /** One safe line of at most MAX_TEXT characters ("…" marks a cut); null becomes "". */
    public static String shorten(String text) {
        if (text == null) {
            return "";
        }
        String clean = CONTROL.matcher(BIDI.matcher(text).replaceAll("")).replaceAll(" ");
        return clean.length() <= MAX_TEXT ? clean : clean.substring(0, MAX_TEXT) + "…";
    }
}
