package com.aegislens.ai;

/**
 * Cleans text that came from logs, files or URLs before it goes into an LLM prompt.
 * Attackers control that text, so it is treated as untrusted data (prompt injection defence).
 */
public final class Sanitizer {

    private Sanitizer() {
    }

    /** Removes control characters, escapes angle brackets (so the text cannot close our delimiter tags), and truncates. */
    public static String clean(String text, int maxLength) {
        if (text == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (char ch : text.toCharArray()) {
            if (ch == '<') {
                sb.append("&lt;");
            } else if (ch == '>') {
                sb.append("&gt;");
            } else if (Character.isISOControl(ch)) {
                sb.append(' ');
            } else {
                sb.append(ch);
            }
        }
        String collapsed = sb.toString().replaceAll("\\s+", " ").trim();
        if (collapsed.length() > maxLength) {
            return collapsed.substring(0, maxLength) + "...";
        }
        return collapsed;
    }
}
