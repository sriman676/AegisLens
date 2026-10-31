package com.aegislens.intel;

import com.aegislens.util.CidrSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Reads a downloaded feed into a set of indicator values, one parser per format. Every value is validated (a real
 * IP literal, a real CIDR, a 64-hex SHA-256) and anything else is skipped, so a changed or hostile feed can only add
 * nonsense lines that are thrown away, never break the app. Comments: lines starting with '#' or ';'.
 */
public final class FeedParsers {

    public static final int MAX_ENTRIES = 1_000_000;
    private static final Pattern SHA256 = Pattern.compile("[0-9a-fA-F]{64}");
    private static final ObjectMapper JSON = new ObjectMapper();

    private FeedParsers() {
    }

    /** The values in body for this feed's format and kind. */
    public static Set<String> parse(FeedDefinition feed, String body) {
        return switch (feed.format()) {
            case "cidr-lines" -> lines(body, feed.kind(), true);
            case "ip-lines", "hash-lines" -> lines(body, feed.kind(), false);
            case "ndjson-cidr" -> ndjson(body, feed.kind());
            case "json-field" -> jsonField(body, feed.field() == null ? "value" : feed.field(), feed.kind());
            default -> new LinkedHashSet<>();
        };
    }

    /** One value per line; "CIDR ; SBLID" keeps only the part before ';'. Comment and blank lines are skipped. */
    static Set<String> lines(String body, String kind, boolean semicolonFields) {
        Set<String> out = new LinkedHashSet<>();
        for (String raw : body.split("\\R")) {
            String line = raw.strip();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) {
                continue;
            }
            if (semicolonFields && line.contains(";")) {
                line = line.substring(0, line.indexOf(';')).strip();
            }
            add(out, line, kind);
        }
        return out;
    }

    /** One JSON object per line with a "cidr" field; the metadata line (it has "type") is skipped. */
    static Set<String> ndjson(String body, String kind) {
        Set<String> out = new LinkedHashSet<>();
        for (String raw : body.split("\\R")) {
            String line = raw.strip();
            if (line.isEmpty()) {
                continue;
            }
            try {
                JsonNode node = JSON.readTree(line);
                if (node != null && node.isObject() && !node.has("type")) {
                    add(out, node.path("cidr").asText(""), kind);
                }
            } catch (IOException notJson) {
                // a broken line is skipped
            }
        }
        return out;
    }

    /** A JSON array of objects; the value is read from field. */
    static Set<String> jsonField(String body, String field, String kind) {
        Set<String> out = new LinkedHashSet<>();
        try {
            JsonNode root = JSON.readTree(body);
            if (root != null && root.isArray()) {
                for (JsonNode item : root) {
                    add(out, item.path(field).asText(""), kind);
                }
            }
        } catch (IOException notJson) {
            // zero entries: the updater keeps the old data and reports it
        }
        return out;
    }

    private static void add(Set<String> out, String value, String kind) {
        if (out.size() >= MAX_ENTRIES) {
            return;
        }
        String v = value.strip();
        boolean ok = switch (kind) {
            case "IP" -> CidrSet.literal(v).isPresent();
            case "CIDR" -> v.contains("/") ? new CidrSet().add(v) : CidrSet.literal(v).isPresent();
            case "HASH" -> SHA256.matcher(v).matches();
            default -> false;
        };
        if (ok) {
            out.add(kind.equals("HASH") ? v.toLowerCase(Locale.ROOT) : v);
        }
    }
}
