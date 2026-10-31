package com.aegislens.web;

import com.aegislens.core.AnalysisException;
import com.aegislens.core.Analyzer;
import com.aegislens.core.Finding;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Static checks on a page's HTML (WEB-005): a form that sends to another site, a password field on a plain-http page,
 * a hidden iframe, a meta refresh to another site, and script obfuscation (eval, atob, fromCharCode, unescape). The
 * HTML is only scanned as text with simple bounded patterns: no parser runs scripts, nothing is submitted or loaded.
 * Score: 30 for one indicator, +15 for each more, max 80 (the README rule table).
 */
public final class HtmlAnalyzer extends Analyzer<String> {

    public static final String RULE = "WEB-005";
    static final int FIRST = 30;
    static final int PER_EXTRA = 15;
    static final int MAX = 80;
    public static final int MAX_HTML = 1024 * 1024;
    private static final Pattern TAG = Pattern.compile("<\\s*(form|input|iframe|meta)\\b([^>]{0,2000})>", Pattern.CASE_INSENSITIVE);
    private static final Pattern ATTR = Pattern.compile("([a-zA-Z-]{1,40})\\s*=\\s*(\"[^\"]{0,2000}\"|'[^']{0,2000}'|[^\\s>]{1,2000})");
    private static final Pattern HIDDEN = Pattern.compile("(?i)(^|\\s)hidden(\\s|$|/)");
    private static final Pattern OBFUSCATION = Pattern.compile("(?i)\\b(eval|atob|unescape)\\s*\\(|fromCharCode");

    public HtmlAnalyzer() {
        super("HTML checks");
    }

    /** HTML without a known address: cross-site and http checks are skipped. */
    @Override
    public List<Finding> analyze(String html) throws AnalysisException {
        return analyze(html, null);
    }

    /** HTML fetched from page (used to tell "another site" and plain http). */
    public List<Finding> analyze(String html, URI page) throws AnalysisException {
        if (html == null) {
            throw new AnalysisException("No page content to check.");
        }
        String text = html.length() > MAX_HTML ? html.substring(0, MAX_HTML) : html;
        String host = page == null || page.getHost() == null ? null : page.getHost().toLowerCase(Locale.ROOT);
        boolean plainHttp = page != null && "http".equalsIgnoreCase(page.getScheme());
        Map<String, String> indicators = new LinkedHashMap<>();
        Matcher tag = TAG.matcher(text);
        while (tag.find()) {
            String name = tag.group(1).toLowerCase(Locale.ROOT);
            Map<String, String> a = attributes(tag.group(2));
            switch (name) {
                case "form" -> {
                    String target = otherHost(a.get("action"), host);
                    if (target != null) {
                        indicators.putIfAbsent("form-elsewhere", "a form sends your input to " + target);
                    }
                }
                case "input" -> {
                    if ("password".equalsIgnoreCase(a.get("type")) && plainHttp) {
                        indicators.putIfAbsent("password-http", "a password field on an unencrypted (http) page");
                    }
                }
                case "iframe" -> {
                    if (hidden(a, tag.group(2))) {
                        indicators.putIfAbsent("hidden-iframe", "a hidden iframe loads " + a.getOrDefault("src", "content"));
                    }
                }
                default -> {                                    // meta
                    String content = a.getOrDefault("content", "");
                    int at = content.toLowerCase(Locale.ROOT).indexOf("url=");
                    String target = at < 0 ? null : otherHost(content.substring(at + 4), host);
                    if ("refresh".equalsIgnoreCase(a.get("http-equiv")) && target != null) {
                        indicators.putIfAbsent("meta-refresh", "the page forwards you to " + target);
                    }
                }
            }
        }
        Matcher obf = OBFUSCATION.matcher(text);
        if (obf.find()) {
            indicators.put("obfuscation", "obfuscated script (" + obf.group() + ")");
        }
        if (indicators.isEmpty()) {
            return List.of();
        }
        int score = Math.min(MAX, FIRST + PER_EXTRA * (indicators.size() - 1));
        String target = page == null ? "page" : page.toString();
        return List.of(new Finding("web", target, RULE, score, "Suspicious page: " + String.join("; ", indicators.values()),
                indicators, null));
    }

    private static Map<String, String> attributes(String text) {
        Map<String, String> a = new LinkedHashMap<>();
        Matcher m = ATTR.matcher(text);
        while (m.find()) {
            String v = m.group(2);
            if (v.startsWith("\"") || v.startsWith("'")) {
                v = v.substring(1, v.length() - 1);
            }
            a.putIfAbsent(m.group(1).toLowerCase(Locale.ROOT), v.strip());
        }
        return a;
    }

    /** The host of an absolute http(s) address that is not the page's own host, else null. */
    private static String otherHost(String address, String ownHost) {
        if (address == null) {
            return null;
        }
        try {
            URI u = URI.create(address.strip().replace("'", "").replace("\"", ""));
            String h = u.getHost();
            if (h == null || !(u.getScheme() != null && u.getScheme().toLowerCase(Locale.ROOT).startsWith("http"))) {
                return null;                                      // relative: same site
            }
            h = h.toLowerCase(Locale.ROOT);
            return ownHost != null && (h.equals(ownHost) || h.endsWith("." + ownHost)) ? null : h;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Zero size, the bare "hidden" attribute, or a style that hides it. */
    private static boolean hidden(Map<String, String> a, String rawTag) {
        String style = a.getOrDefault("style", "").toLowerCase(Locale.ROOT).replace(" ", "");
        return "0".equals(a.get("width")) || "0".equals(a.get("height")) || HIDDEN.matcher(rawTag).find()
                || style.contains("display:none") || style.contains("visibility:hidden");
    }
}
