package com.aegislens.web;

import com.aegislens.core.AnalysisException;
import com.aegislens.core.Analyzer;
import com.aegislens.core.Finding;
import com.aegislens.util.CidrSet;
import com.aegislens.util.InjectionPatterns;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Static checks on a URL (nothing is fetched): WEB-001 phishing indicators scored per the README rule table (40 for one, +15 per
 * extra, max 90; a lookalike alone at least 75), WEB-002 injection patterns in the path or query (70), and WEB-004 when
 * the domain or URL is on a threat list (90). Short links, login words and very long host names are noted in the
 * evidence but not scored, so github.com/login stays clean.
 */
public final class UrlAnalyzer extends Analyzer<String> {

    public static final String PHISHING = "WEB-001";
    public static final String INJECTION = "WEB-002";
    public static final String THREAT_LIST = "WEB-004";
    static final int FIRST = 40;
    static final int PER_EXTRA = 15;
    static final int MAX = 90;
    static final int LOOKALIKE_MIN = 75;
    static final int INJECTION_SCORE = 70;
    static final int THREAT_LIST_SCORE = 90;
    public static final int MAX_URL = 4096;
    static final Set<String> SUSPICIOUS_TLDS = Set.of("zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
            "country", "kim", "work", "loan", "racing", "rest", "cam", "monster");
    static final Set<String> SHORTENERS = Set.of("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy");
    static final Set<String> LOGIN_WORDS = Set.of("login", "signin", "verify", "account", "secure", "update", "password", "wallet");
    static final int MANY_LABELS = 5;

    private final LookalikeChecker lookalikes;
    private final InjectionPatterns injection;
    private final Predicate<String> onThreatList;

    /** onThreatList answers "is this domain or URL on an indicator list?" (the app asks the ioc table). */
    public UrlAnalyzer(LookalikeChecker lookalikes, InjectionPatterns injection, Predicate<String> onThreatList) {
        super("URL checks");
        this.lookalikes = lookalikes;
        this.injection = injection;
        this.onThreatList = onThreatList;
    }

    /** Checks one URL as typed; a URL without a scheme is read as http://. */
    @Override
    public List<Finding> analyze(String url) throws AnalysisException {
        if (url == null || url.isBlank() || url.length() > MAX_URL) {
            throw new AnalysisException("Type a web address of at most " + MAX_URL + " characters.");
        }
        String t = url.strip();
        try {
            return analyze(new URI(t.contains("://") ? t : "http://" + t), t);
        } catch (URISyntaxException e) {
            throw new AnalysisException("Not a valid web address: " + e.getReason());
        }
    }

    /** Checks an already parsed address. */
    public List<Finding> analyze(URI uri) throws AnalysisException {
        return analyze(uri, uri.toString());
    }

    private List<Finding> analyze(URI uri, String original) throws AnalysisException {
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (host.isEmpty() || !("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))) {
            throw new AnalysisException("Only http and https addresses with a host name can be checked.");
        }
        List<Finding> findings = new ArrayList<>();
        phishing(uri, host, original).ifPresent(findings::add);
        injection.find(uri.getRawPath() + "?" + (uri.getRawQuery() == null ? "" : uri.getRawQuery())).ifPresent(hit ->
                findings.add(new Finding("web", original, INJECTION, INJECTION_SCORE,
                        "Injection pattern (" + hit.kind() + ") in the address", Map.of("kind", hit.kind(), "match", hit.match()), null)));
        if (onThreatList.test(host) || onThreatList.test(original)) {
            findings.add(new Finding("web", original, THREAT_LIST, THREAT_LIST_SCORE,
                    host + " is on a threat-intelligence list", Map.of("host", host), null));
        }
        return findings;
    }

    private Optional<Finding> phishing(URI uri, String host, String original) {
        Map<String, String> indicators = new LinkedHashMap<>();
        Optional<String> imitated = lookalikes.imitates(host);
        imitated.ifPresent(real -> indicators.put("lookalike", "imitates " + real));
        if (CidrSet.literal(host.replace("[", "").replace("]", "")).isPresent()) {
            indicators.put("raw-ip", "the host is a bare IP address");
        }
        if (uri.getRawUserInfo() != null) {
            indicators.put("at-sign", "text before '@' hides the real destination " + host);
        }
        if (original.toLowerCase(Locale.ROOT).contains("xn--")) {
            indicators.put("punycode", "punycode (xn--) can hide look-alike letters");
        }
        String tld = host.substring(host.lastIndexOf('.') + 1);
        if (SUSPICIOUS_TLDS.contains(tld)) {
            indicators.put("tld", "." + tld + " is often used for abuse");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            indicators.put("no-https", "not encrypted (http)");
        }
        boolean plainHttpOnly = indicators.size() == 1 && indicators.containsKey("no-https");
        if (indicators.isEmpty() || plainHttpOnly) {
            return Optional.empty();                   // plain http alone is too common to report
        }
        int score = Math.min(MAX, FIRST + PER_EXTRA * (indicators.size() - 1));
        if (imitated.isPresent()) {
            score = Math.max(score, LOOKALIKE_MIN);
        }
        Map<String, String> evidence = new LinkedHashMap<>(indicators);
        notes(uri, host).forEach(evidence::put);
        return Optional.of(new Finding("web", original, PHISHING, score, "Phishing indicators: "
                + String.join(", ", indicators.values()), evidence, null));
    }

    /** Context that is not scored on its own. */
    private static Map<String, String> notes(URI uri, String host) {
        Map<String, String> notes = new LinkedHashMap<>();
        if (SHORTENERS.contains(host)) {
            notes.put("note-shortener", "a link shortener hides the destination");
        }
        String text = (uri.getRawPath() + " " + host).toLowerCase(Locale.ROOT);
        LOGIN_WORDS.stream().filter(text::contains).findFirst().ifPresent(w -> notes.put("note-words", "asks to '" + w + "'"));
        if (host.split("\\.").length >= MANY_LABELS) {
            notes.put("note-subdomains", "many sub-domains");
        }
        return notes;
    }
}
