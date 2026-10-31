package com.aegislens.web;

import com.aegislens.core.AnalysisException;
import com.aegislens.core.Finding;
import com.aegislens.util.IpRules;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * Fetches ONE address the user typed (after they agreed) and reports missing security headers (WEB-003) and the page
 * HTML for HtmlAnalyzer. SSRF guard: http/https only; the host is resolved ONCE
 * and EVERY address must be public (no loopback, private, link-local, multicast or unique-local); the request then goes
 * to that checked address (PinnedHttp), so a second DNS answer cannot send it inside your network (no rebinding). The
 * same happens again for each redirect; at most 3 redirects, GET only, 5 s timeouts, 1 MB body cap, no cookies.
 */
public final class HeaderChecker {

    public static final String RULE = "WEB-003";
    public static final int MAX_REDIRECTS = 3;
    public static final long MAX_BODY = 1024 * 1024;
    static final int FIRST = 20;
    static final int PER_EXTRA = 5;
    static final int MAX = 40;
    static final List<String> SECURITY_HEADERS = List.of("strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options");

    /** Turns a host name into its addresses (InetAddress::getAllByName in the app; a fake one in tests). */
    @FunctionalInterface
    public interface Resolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    /** What one check found: the final address, its status, the missing headers and the page text. */
    public record Result(URI finalUrl, int status, List<String> missing, String html, List<URI> chain) {
    }

    private final Resolver resolver;
    private final Predicate<InetAddress> allowed;

    /** The real guard: only public addresses. */
    public HeaderChecker() {
        this(InetAddress::getAllByName, a -> IpRules.whyNotBlockable(a.getHostAddress()).isEmpty());
    }

    /** For tests: a fake resolver and an address rule (for example allowing 127.0.0.1 for a local fake server). */
    HeaderChecker(Resolver resolver, Predicate<InetAddress> allowed) {
        this.resolver = resolver;
        this.allowed = allowed;
    }

    /** Fetches the typed address, following at most 3 redirects, each one checked by the guard. */
    public Result fetch(String typed) throws AnalysisException {
        URI uri = parse(typed);
        List<URI> chain = new ArrayList<>();
        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            InetAddress checked = guard(uri);
            chain.add(uri);
            PinnedHttp.Response r = get(uri, checked);
            String location = r.headers().get("location");
            if (r.status() / 100 == 3 && location != null) {
                uri = parse(uri.resolve(location.strip()).toString());
                continue;
            }
            List<String> missing = new ArrayList<>();
            for (String h : SECURITY_HEADERS) {
                boolean httpsOnly = h.equals("strict-transport-security") && !"https".equalsIgnoreCase(uri.getScheme());
                if (!httpsOnly && !r.headers().containsKey(h)) {
                    missing.add(h);
                }
            }
            return new Result(uri, r.status(), missing, r.body(), chain);
        }
        throw new AnalysisException("Stopped after " + MAX_REDIRECTS + " redirects (" + chain.get(chain.size() - 1) + ").");
    }

    /** WEB-003 for the missing headers of a result, if any (20 for the first, +5 each, max 40). */
    public static Optional<Finding> headerFinding(Result r) {
        if (r.missing().isEmpty()) {
            return Optional.empty();
        }
        Map<String, String> evidence = new LinkedHashMap<>();
        evidence.put("missing", String.join(", ", r.missing()));
        evidence.put("status", String.valueOf(r.status()));
        int score = Math.min(MAX, FIRST + PER_EXTRA * (r.missing().size() - 1));
        return Optional.of(new Finding("web", r.finalUrl().toString(), RULE, score,
                "Missing security headers: " + String.join(", ", r.missing()), evidence, null));
    }

    private static URI parse(String typed) throws AnalysisException {
        try {
            URI u = URI.create(typed.strip().contains("://") ? typed.strip() : "https://" + typed.strip());
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
            if (!(scheme.equals("http") || scheme.equals("https")) || u.getHost() == null) {
                throw new AnalysisException("Only http and https addresses can be fetched.");
            }
            return u;
        } catch (IllegalArgumentException e) {
            throw new AnalysisException("Not a valid web address.");
        }
    }

    /** The SSRF guard: every address of the host must be allowed; returns the one we will connect to. */
    private InetAddress guard(URI uri) throws AnalysisException {
        InetAddress[] addresses;
        try {
            addresses = resolver.resolve(uri.getHost());
        } catch (UnknownHostException e) {
            throw new AnalysisException("The name " + uri.getHost() + " could not be found.");
        }
        for (InetAddress a : addresses) {
            if (!allowed.test(a)) {
                throw new AnalysisException("Refused: " + uri.getHost() + " points to " + a.getHostAddress()
                        + ", a private or local address. AegisLens never fetches addresses inside your own network (SSRF guard).");
            }
        }
        if (addresses.length == 0) {
            throw new AnalysisException("The name " + uri.getHost() + " has no address.");
        }
        return addresses[0];
    }

    private static PinnedHttp.Response get(URI uri, InetAddress address) throws AnalysisException {
        try {
            return PinnedHttp.get(uri, address, MAX_BODY);
        } catch (IOException e) {
            throw new AnalysisException("Could not fetch " + uri.getHost() + ": " + e.getMessage());
        }
    }
}
