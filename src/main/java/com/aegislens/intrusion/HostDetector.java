package com.aegislens.intrusion;

import com.aegislens.core.Detector;
import com.aegislens.core.Finding;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Parent of the Sysmon (host) detectors: a Detector&lt;SysmonEvent&gt; that knows its rule ids and builds findings
 * with the event's computer, user and capped raw text as evidence. Scores come from the README rule table (HOST-xxx).
 */
public abstract class HostDetector implements Detector<SysmonEvent> {

    /** Finding source for every host rule. */
    public static final String SOURCE = "sysmon";

    /** Folders where ordinary programs do not live (lower case, Windows separators). */
    static final List<String> USER_FOLDERS = List.of("\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\",
            "\\windows\\temp\\", "\\appdata\\roaming\\");

    /** The rule ids this detector can raise (the engine drops findings of rules switched off in Settings). */
    public abstract Set<String> ruleIds();

    /** A finding about target; evidence keeps the order given, then computer, user and the raw event. */
    protected final Finding finding(String ruleId, SysmonEvent e, String target, int score, String description,
                                    String... evidence) {
        Map<String, String> ev = new LinkedHashMap<>();
        for (int i = 0; i + 1 < evidence.length; i += 2) {
            ev.put(evidence[i], evidence[i + 1]);
        }
        ev.put("computer", e.computer());
        if (!e.get("User").isEmpty()) {
            ev.put("user", e.get("User"));
        }
        ev.put("event", e.raw());
        String what = target.isBlank() ? (e.computer().isBlank() ? "unknown host" : e.computer()) : target;
        return new Finding(SOURCE, what, ruleId, Math.min(100, score), description, ev, e.timestamp());
    }

    /** True when the (lower-case) path is inside one of the USER_FOLDERS. */
    static boolean inUserFolder(String path) {
        String p = path.toLowerCase(java.util.Locale.ROOT);
        return USER_FOLDERS.stream().anyMatch(p::contains);
    }

    /** Case-insensitive pattern (all host patterns avoid nested quantifiers: no catastrophic backtracking). */
    static Pattern regex(String pattern) {
        return Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
    }
}
