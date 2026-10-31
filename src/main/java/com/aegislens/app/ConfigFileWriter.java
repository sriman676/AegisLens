package com.aegislens.app;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

/**
 * Saves start-up options edited in Settings into aegislens.properties. Comments and untouched lines are kept; a changed
 * key is rewritten in place, a new one is appended, and a blank value removes the line (back to the default). The new
 * file is checked with the same rules as --check-config BEFORE it replaces the old one, so a typo can never stop the
 * next start. Values are escaped for the properties format (a Windows path keeps its backslashes). Secret-looking keys
 * are refused: keys stay in environment variables.
 */
public final class ConfigFileWriter {

    private ConfigFileWriter() {
    }

    /** The key=value pairs currently in the file (empty if it does not exist). */
    public static Map<String, String> read(Path file) throws IOException {
        Map<String, String> values = new TreeMap<>();
        if (Files.isRegularFile(file)) {
            Properties p = new Properties();
            try (InputStream in = Files.newInputStream(file)) {
                p.load(in);
            }
            p.stringPropertyNames().forEach(k -> values.put(k, p.getProperty(k)));
        }
        return values;
    }

    /**
     * Applies the changes and returns the problems found; the file is only replaced when the list is empty.
     * dataDir is used for the check (it is not written to the file).
     */
    public static List<String> update(Path file, Map<String, String> changes, Path dataDir) throws IOException {
        List<String> problems = new ArrayList<>();
        for (String key : changes.keySet()) {
            if (!key.matches("[a-z0-9.]+")) {
                problems.add("'" + key + "' is not an option name");
            } else if (AppConfig.isSecret(key)) {
                problems.add(key + " looks like a secret: put it in an environment variable instead");
            }
        }
        if (!problems.isEmpty()) {
            return problems;
        }
        Path temp = Files.createTempFile(file.toAbsolutePath().getParent(), "aegislens", ".properties.tmp");
        try {
            Files.writeString(temp, merge(Files.isRegularFile(file) ? Files.readAllLines(file, StandardCharsets.ISO_8859_1)
                    : List.of(), changes), StandardCharsets.ISO_8859_1);
            AppConfig candidate = AppConfig.load(temp, Map.of(), new String[] {"--" + AppConfig.DATA_DIR + "=" + dataDir});
            problems.addAll(HeadlessMain.problems(candidate));
            if (problems.isEmpty()) {
                move(temp, file);
            }
            return problems;
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /** The new file text: existing lines with changed keys rewritten, then any new keys. */
    static String merge(List<String> lines, Map<String, String> changes) {
        Map<String, String> pending = new LinkedHashMap<>(changes);
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            String key = keyOf(line);
            if (key != null && pending.containsKey(key)) {
                String value = pending.remove(key);
                if (!value.isBlank()) {
                    sb.append(key).append('=').append(escape(value.strip())).append('\n');
                }
            } else {
                sb.append(line).append('\n');
            }
        }
        pending.values().removeIf(String::isBlank);
        if (!pending.isEmpty()) {
            sb.append("# changed in AegisLens Settings on ").append(LocalDate.now()).append('\n');
            pending.forEach((k, v) -> sb.append(k).append('=').append(escape(v.strip())).append('\n'));
        }
        return sb.toString();
    }

    /** The key of a "key=value" line, or null for comments and blank lines. */
    private static String keyOf(String line) {
        String t = line.strip();
        if (t.isEmpty() || t.startsWith("#") || t.startsWith("!") || !t.contains("=")) {
            return null;
        }
        return t.substring(0, t.indexOf('=')).strip();
    }

    /** Properties escaping: backslash doubled, characters outside Latin-1 as backslash-u escapes. */
    static String escape(String value) {
        StringBuilder sb = new StringBuilder();
        for (char ch : value.toCharArray()) {
            if (ch == '\\') {
                sb.append("\\\\");
            } else if (ch > 0xFF || Character.isISOControl(ch)) {
                sb.append(String.format("\\u%04x", (int) ch));
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    private static void move(Path from, Path to) throws IOException {
        try {
            Files.move(from, to, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(from, to, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
