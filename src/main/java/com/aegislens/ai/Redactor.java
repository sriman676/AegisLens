package com.aegislens.ai;

import com.aegislens.core.Finding;
import com.aegislens.util.CidrSet;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Privacy for cloud AI: before a finding leaves the machine, IP addresses become IP-1, IP-2..., the user
 * name becomes USER-1, and file paths are shortened to the file name. The answer that comes back is mapped back so the
 * analyst still sees the real values. One Redactor per request (it remembers that request's mapping).
 */
public final class Redactor {

    private static final Pattern IPV4 = Pattern.compile("(?<![\\d.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])");
    private static final Pattern IPV6 = Pattern.compile("(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])");
    private static final Pattern PATH = Pattern.compile("(?:[A-Za-z]:\\\\|/)(?:[^\\s/\\\\:*?\"<>|]{1,200}[/\\\\]){1,30}([^\\s/\\\\:*?\"<>|]{1,200})");

    private final Map<String, String> placeholders = new LinkedHashMap<>();    // original -> placeholder
    private int ips;
    private int users;

    /** A copy of the finding with private values replaced. Raw log lines are left out entirely. */
    public Finding redact(Finding f) {
        String user = f.evidence().get("user");
        if (user != null && user.length() >= 2) {
            placeholders.putIfAbsent(user, "USER-" + (++users));
        }
        Map<String, String> evidence = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : f.evidence().entrySet()) {
            if (!e.getKey().equals("line")) {
                evidence.put(e.getKey(), text(e.getValue()));
            }
        }
        return new Finding(f.source(), text(f.target()), f.ruleId(), f.score(), text(f.description()), evidence, f.timestamp());
    }

    /** Replaces users, IPs and paths in one piece of text. */
    public String text(String s) {
        if (s == null) {
            return null;
        }
        String out = s;
        for (Map.Entry<String, String> e : placeholders.entrySet()) {
            if (e.getValue().startsWith("USER-")) {
                out = out.replace(e.getKey(), e.getValue());
            }
        }
        out = replaceIps(out, IPV4);
        out = replaceIps(out, IPV6);
        return PATH.matcher(out).replaceAll(m -> Matcher.quoteReplacement(m.group(1)));
    }

    private String replaceIps(String s, Pattern p) {
        Matcher m = p.matcher(s);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String ip = m.group();
            if (CidrSet.literal(ip).isEmpty()) {
                m.appendReplacement(sb, Matcher.quoteReplacement(ip));     // looked like an IP (a time "02:14:20"), is not one
                continue;
            }
            String ph = placeholders.computeIfAbsent(ip, k -> "IP-" + (++ips));
            m.appendReplacement(sb, Matcher.quoteReplacement(ph));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /** Puts the real values back into the provider's answer (longest placeholder first: IP-12 before IP-1). */
    public String restore(String answer) {
        if (answer == null) {
            return null;
        }
        List<Map.Entry<String, String>> byLength = new ArrayList<>(placeholders.entrySet());
        byLength.sort((a, b) -> b.getValue().length() - a.getValue().length());
        String out = answer;
        for (Map.Entry<String, String> e : byLength) {
            out = out.replace(e.getValue(), e.getKey());
        }
        return out;
    }

    public boolean changedAnything() {
        return !placeholders.isEmpty();
    }
}
