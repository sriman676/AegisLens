package com.aegislens.ai;

import com.aegislens.ai.LlmException.Kind;
import com.aegislens.core.Finding;
import com.aegislens.net.RetryPolicy;
import com.aegislens.util.CidrSet;
import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Asks a SplitShield-XAI installation (the analyst's SOC companion) what it knows about the finding's IP, user or file:
 * GET {url}/api/v1/search?q=... with a Bearer token from SPLITSHIELD_TOKEN, over HTTPS pinned to SplitShield's
 * self-signed certificate. The answer is correlation context ("SplitShield saw 12 related events, sources ..., ATT&CK
 * techniques ..."), not a language-model text; the service appends it to the explanation. Everything SplitShield
 * returns is untrusted text and is sanitised and capped. Read-only: the API cannot change anything in SplitShield.
 */
public class SplitShieldProvider extends HttpLlmProvider {

    static final int MAX_FIELD = 120;
    static final int MAX_SOURCES = 5;
    static final int MAX_TECHNIQUES = 8;

    private final String baseUrl;
    private final String token;

    public SplitShieldProvider(String baseUrl, String token, HttpClient client, RetryPolicy retry) {
        super(client, retry);
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.token = token;
    }

    @Override
    public String name() {
        return "splitshield";
    }

    @Override
    public String explain(Finding finding) throws LlmException {
        requireKey(token, "SplitShield (SPLITSHIELD_TOKEN)");
        String subject = subject(finding);
        URI uri = URI.create(baseUrl + "/api/v1/search?limit=50&q=" + URLEncoder.encode(subject, StandardCharsets.UTF_8));
        return summarise(subject, json(get(uri, Map.of("authorization", "Bearer " + token))));
    }

    /** What to search for: the IP if the target is one, else the user from the evidence, else the file name. */
    static String subject(Finding f) {
        String target = f.target() == null ? "" : f.target().trim();
        if (CidrSet.literal(target).isPresent()) {
            return target;
        }
        String user = f.evidence().get("user");
        if (user != null && !user.isBlank()) {
            return user;
        }
        // The target is text that may come from Windows or Unix, so split on both separators
        // (Path.getFileName() would only know the separator of the OS we run on).
        int cut = Math.max(target.lastIndexOf('/'), target.lastIndexOf('\\'));
        return cut >= 0 && cut < target.length() - 1 ? target.substring(cut + 1) : target;
    }

    String summarise(String subject, JsonNode reply) throws LlmException {
        if (!reply.has("rows") && !reply.has("count")) {
            throw new LlmException(Kind.BAD_RESPONSE, "SplitShield reply had no search result");
        }
        long count = reply.path("count").asLong(reply.path("rows").size());
        String shown = Sanitizer.clean(subject, MAX_FIELD);
        if (count == 0) {
            return "SplitShield-XAI has no stored events about " + shown + ".";
        }
        Map<String, Integer> bySource = new LinkedHashMap<>();
        Set<String> techniques = new LinkedHashSet<>();
        for (JsonNode row : reply.path("rows")) {
            bySource.merge(Sanitizer.clean(row.path("source").asText("?"), 40), 1, Integer::sum);
            for (String t : row.path("techniques").asText("").split(",")) {
                if (!t.isBlank() && techniques.size() < MAX_TECHNIQUES) {
                    techniques.add(Sanitizer.clean(t.trim(), 20));
                }
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append("SplitShield-XAI has ").append(count).append(count == 1 ? " stored event" : " stored events")
          .append(" about ").append(shown);
        String understood = reply.path("understood").asText("");
        if (!understood.isBlank()) {
            sb.append(" (searched for: ").append(Sanitizer.clean(understood, MAX_FIELD)).append(')');
        }
        sb.append('.');
        if (!bySource.isEmpty()) {
            sb.append("\nBy source: ");
            bySource.entrySet().stream().limit(MAX_SOURCES)
                    .forEach(e -> sb.append(e.getKey()).append(" (").append(e.getValue()).append("), "));
            sb.setLength(sb.length() - 2);
        }
        if (!techniques.isEmpty()) {
            sb.append("\nATT&CK techniques: ").append(String.join(", ", techniques));
        }
        JsonNode latest = reply.path("rows").path(0);
        if (!latest.isMissingNode()) {
            sb.append("\nLatest: ").append(Sanitizer.clean(latest.path("time").asText(""), 30)).append(' ')
              .append(Sanitizer.clean(latest.path("kind").asText(""), 40)).append(": ")
              .append(Sanitizer.clean(latest.path("detail").asText(""), MAX_FIELD));
        }
        return sb.toString();
    }
}
