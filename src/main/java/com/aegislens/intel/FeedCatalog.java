package com.aegislens.intel;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Logger;

/**
 * Reads the feed list: the bundled /intel/feeds.properties, then the user's copy in the data folder (whose entries
 * replace bundled ones key by key). Invalid entries are skipped with a log line instead of stopping the app.
 * Only https URLs are accepted (http only with allow.http=true, which exists for tests).
 */
public final class FeedCatalog {

    public static final String FILE_NAME = "feeds.properties";
    public static final Set<String> FORMATS = Set.of("cidr-lines", "ndjson-cidr", "ip-lines", "hash-lines", "json-field");
    public static final Set<String> KINDS = Set.of("IP", "CIDR", "HASH");
    private static final Logger LOG = Logger.getLogger(FeedCatalog.class.getName());

    private FeedCatalog() {
    }

    /** Bundled defaults overlaid by dataFolder/feeds.properties if it exists. */
    public static List<FeedDefinition> load(Path dataFolder) throws IOException {
        Properties p = new Properties();
        try (InputStream in = FeedCatalog.class.getResourceAsStream("/intel/" + FILE_NAME)) {
            if (in != null) {
                p.load(in);
            }
        }
        Path user = dataFolder == null ? null : dataFolder.resolve(FILE_NAME);
        if (user != null && Files.isRegularFile(user)) {
            try (InputStream in = Files.newInputStream(user)) {
                p.load(in);
            }
        }
        return parse(p);
    }

    /** All valid feeds in the properties, sorted by name. */
    public static List<FeedDefinition> parse(Properties p) {
        Set<String> names = new TreeSet<>();
        for (String key : p.stringPropertyNames()) {
            if (key.startsWith("feed.") && key.indexOf('.', 5) > 5) {
                names.add(key.substring(5, key.indexOf('.', 5)));
            }
        }
        List<FeedDefinition> feeds = new ArrayList<>();
        for (String name : names) {
            try {
                feeds.add(one(p, name));
            } catch (IllegalArgumentException e) {
                LOG.warning("Skipping feed '" + name + "': " + e.getMessage());
            }
        }
        return feeds;
    }

    private static FeedDefinition one(Properties p, String name) {
        String prefix = "feed." + name + ".";
        String url = p.getProperty(prefix + "url", "").trim();
        URI uri = URI.create(url);
        boolean allowHttp = Boolean.parseBoolean(p.getProperty(prefix + "allow.http", "false"));
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !(allowHttp && "http".equalsIgnoreCase(uri.getScheme()))) {
            throw new IllegalArgumentException("url must be https");
        }
        String format = p.getProperty(prefix + "format", "").trim().toLowerCase(Locale.ROOT);
        if (!FORMATS.contains(format)) {
            throw new IllegalArgumentException("unknown format " + format);
        }
        String kind = p.getProperty(prefix + "kind", "").trim().toUpperCase(Locale.ROOT);
        if (!KINDS.contains(kind)) {
            throw new IllegalArgumentException("kind must be IP, CIDR or HASH");
        }
        long hours = Long.parseLong(p.getProperty(prefix + "interval.hours", "24").trim());
        long minMinutes = Long.parseLong(p.getProperty(prefix + "min.interval.minutes", "60").trim());
        if (hours < 1 || minMinutes < 1) {
            throw new IllegalArgumentException("intervals must be positive");
        }
        return new FeedDefinition(name, uri, format, kind, Boolean.parseBoolean(p.getProperty(prefix + "enabled", "false")),
                Duration.ofHours(hours), Duration.ofMinutes(minMinutes), blankToNull(p.getProperty(prefix + "header.name")),
                blankToNull(p.getProperty(prefix + "header.env")), Boolean.parseBoolean(p.getProperty(prefix + "allow.empty", "false")),
                Boolean.parseBoolean(p.getProperty(prefix + "c2", "false")), blankToNull(p.getProperty(prefix + "field")),
                p.getProperty(prefix + "attribution", name).trim());
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}
