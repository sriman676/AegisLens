package com.aegislens.app;

import com.aegislens.db.IocRepository;
import com.aegislens.intel.FeedCatalog;
import com.aegislens.intel.FeedDefinition;
import com.aegislens.util.CidrSet;

import java.io.IOException;
import java.io.InputStream;
import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * Your own watch lists and block lists (Threat intel screen). Own indicators are stored in the ioc table with source
 * "manual" (or "manual-c2" for a botnet controller, which scores 90 like the C2 feeds) and reach the live detectors at
 * once. Own feeds are written to feeds.properties in the data folder, checked with the same rules as the bundled ones,
 * and are used after Restart now. Every value is normalised first (canonical IP, lower-case hash, punycode domain).
 */
public final class OwnIntel {

    public static final String SOURCE = "manual";
    public static final String C2_SOURCE = "manual-c2";
    /** Kinds you can add by hand. HASH means SHA-256, the hash the scanner looks up. */
    public static final List<String> KINDS = List.of("IP", "CIDR", "HASH", "DOMAIN", "URL");

    private final ScanCoordinator coordinator;
    private final IocRepository iocs;

    public OwnIntel(ScanCoordinator coordinator) {
        this.coordinator = coordinator;
        this.iocs = new IocRepository(coordinator.database());
    }

    // ---------------------------------------------------------------- own indicators

    /** Checks, normalises and stores one indicator; IPs and ranges apply to the live detectors at once. */
    public String add(String kind, String value, boolean c2, String note) throws AnalystActions.RefusedException, SQLException {
        String clean = normalise(kind, value);
        boolean added = iocs.add(kind, clean, c2 ? C2_SOURCE : SOURCE, Branding.cleanName(note));
        coordinator.reloadThreatIntel();
        return added ? "Added " + kind + " " + clean + "." : clean + " is already on a list.";
    }

    public List<IocRepository.IocEntry> list() throws SQLException {
        return iocs.findBySources(SOURCE, C2_SOURCE);
    }

    /** Removes one of your own entries (feed entries cannot be removed here). */
    public boolean remove(long id) throws SQLException {
        boolean removed = iocs.deleteById(id, SOURCE, C2_SOURCE);
        coordinator.reloadThreatIntel();
        return removed;
    }

    /** The stored form of a value, or RefusedException saying what is wrong. */
    public static String normalise(String kind, String value) throws AnalystActions.RefusedException {
        String v = value == null ? "" : value.strip();
        if (v.isEmpty()) {
            throw new AnalystActions.RefusedException("Type a value first.");
        }
        return switch (kind) {
            case "IP" -> CidrSet.literal(v).map(a -> a.getHostAddress())
                    .orElseThrow(() -> new AnalystActions.RefusedException("'" + v + "' is not an IP address."));
            case "CIDR" -> {
                if (!v.contains("/") || !new CidrSet().add(v)) {
                    throw new AnalystActions.RefusedException("'" + v + "' is not a range like 203.0.113.0/24.");
                }
                yield v.toLowerCase(Locale.ROOT);
            }
            case "HASH" -> {
                String h = v.toLowerCase(Locale.ROOT);
                if (!h.matches("[0-9a-f]{64}")) {
                    throw new AnalystActions.RefusedException("A file hash must be a SHA-256 (64 hex characters).");
                }
                yield h;
            }
            case "DOMAIN" -> domain(v);
            case "URL" -> url(v);
            default -> throw new AnalystActions.RefusedException("Unknown kind " + kind);
        };
    }

    private static String domain(String v) throws AnalystActions.RefusedException {
        try {
            String ascii = IDN.toASCII(v.toLowerCase(Locale.ROOT).replaceAll("\\.$", ""), IDN.USE_STD3_ASCII_RULES);
            if (!ascii.matches("([a-z0-9-]{1,63}\\.)+[a-z0-9-]{2,63}")) {
                throw new IllegalArgumentException(v);
            }
            return ascii;
        } catch (IllegalArgumentException e) {
            throw new AnalystActions.RefusedException("'" + v + "' is not a domain like login-example.com.");
        }
    }

    private static String url(String v) throws AnalystActions.RefusedException {
        try {
            URI uri = new URI(v);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            if (!(scheme.equals("http") || scheme.equals("https")) || uri.getHost() == null) {
                throw new URISyntaxException(v, "needs http(s) and a host");
            }
            return uri.normalize().toString();
        } catch (URISyntaxException e) {
            throw new AnalystActions.RefusedException("'" + v + "' is not a web address like https://x.example/login.");
        }
    }

    // ---------------------------------------------------------------- own feeds

    /** Adds (or replaces) one feed in the data folder's feeds.properties after checking it like the bundled ones. */
    public static void addFeed(Path dataDir, String name, String url, String format, String kind, String attribution)
            throws AnalystActions.RefusedException, IOException {
        if (name == null || !name.matches("[a-z0-9-]{2,30}")) {
            throw new AnalystActions.RefusedException("A feed name uses 2 to 30 of a-z, 0-9 and '-'.");
        }
        Map<String, String> keys = new LinkedHashMap<>();
        String p = "feed." + name + ".";
        keys.put(p + "url", url == null ? "" : url.strip());
        keys.put(p + "format", format);
        keys.put(p + "kind", kind);
        keys.put(p + "enabled", "true");
        keys.put(p + "interval.hours", "24");
        keys.put(p + "min.interval.minutes", "60");
        keys.put(p + "attribution", Branding.cleanName(attribution == null || attribution.isBlank() ? name : attribution));
        Properties candidate = new Properties();
        candidate.putAll(keys);
        List<FeedDefinition> parsed = FeedCatalog.parse(candidate);
        if (parsed.isEmpty()) {
            throw new AnalystActions.RefusedException("Not added: the address must start with https:// and the format and kind must match.");
        }
        write(dataDir, keys);
    }

    /** Turns a feed (yours or a bundled one) on or off. */
    public static void setFeedEnabled(Path dataDir, String name, boolean enabled) throws IOException {
        write(dataDir, Map.of("feed." + name + ".enabled", String.valueOf(enabled)));
    }

    /** Removes a feed you added (its lines in the data folder's feeds.properties). Bundled feeds can only be turned off. */
    public static boolean removeFeed(Path dataDir, String name) throws IOException {
        Path file = dataDir.resolve(FeedCatalog.FILE_NAME);
        if (!Files.isRegularFile(file)) {
            return false;
        }
        Map<String, String> blanks = new LinkedHashMap<>();
        Properties own = new Properties();
        try (InputStream in = Files.newInputStream(file)) {
            own.load(in);
        }
        for (String key : own.stringPropertyNames()) {
            if (key.startsWith("feed." + name + ".")) {
                blanks.put(key, "");
            }
        }
        if (blanks.isEmpty()) {
            return false;
        }
        write(dataDir, blanks);
        return true;
    }

    private static void write(Path dataDir, Map<String, String> changes) throws IOException {
        Path file = dataDir.resolve(FeedCatalog.FILE_NAME);
        List<String> lines = Files.isRegularFile(file) ? Files.readAllLines(file, StandardCharsets.ISO_8859_1) : new ArrayList<>();
        if (lines.isEmpty()) {
            lines.add("# Your feeds and changes to the bundled ones (written by AegisLens Threat intel; you may edit it).");
        }
        Files.createDirectories(dataDir);
        Files.writeString(file, ConfigFileWriter.merge(lines, changes), StandardCharsets.ISO_8859_1);
    }
}
