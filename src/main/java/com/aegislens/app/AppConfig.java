package com.aegislens.app;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Application settings from three sources, later ones winning: aegislens.properties in the data folder,
 * then environment variables AEGISLENS_&lt;KEY&gt; (dots become underscores, upper case), then command-line --key=value.
 * Secrets never come from here: API keys are read only from their own environment variables by the ai package.
 */
public final class AppConfig {

    public static final String DATA_DIR = "data.dir";
    public static final String DEDUPE_COOLDOWN_MINUTES = "dedupe.cooldown.minutes";
    public static final String BUS_CAPACITY = "bus.capacity";
    public static final String SCAN_THREADS = "scan.threads";

    public static final int DEFAULT_COOLDOWN_MINUTES = 10;
    public static final int DEFAULT_BUS_CAPACITY = 1000;
    public static final int DEFAULT_SCAN_THREADS = 2;

    private static final Logger LOG = Logger.getLogger(AppConfig.class.getName());
    private static final Pattern SECRET = Pattern.compile("(?i).*(api[_.-]?key|secret|token|password|passwd).*");
    private static final String ENV_PREFIX = "AEGISLENS_";

    private final Map<String, String> values;

    private AppConfig(Map<String, String> values) {
        this.values = values;
    }

    /** Defaults only (used in tests and when nothing is configured). */
    public static AppConfig defaults() {
        return new AppConfig(new HashMap<>());
    }

    /** Real start-up: the default data folder's properties file, the process environment and the CLI arguments. */
    public static AppConfig load(String[] args) throws IOException {
        Map<String, String> cli = parseArgs(args);
        Path dataDir = cli.containsKey(DATA_DIR) ? Path.of(cli.get(DATA_DIR)) : AppPaths.defaultPaths().dataDir();
        return load(new AppPaths(dataDir).configFile(), System.getenv(), args);
    }

    /** Loads from an explicit file, environment map and arguments (testable without touching the real environment). */
    public static AppConfig load(Path propertiesFile, Map<String, String> env, String[] args) throws IOException {
        Map<String, String> values = new HashMap<>();
        putAll(values, readProperties(propertiesFile), "file");
        putAll(values, fromEnv(env), "environment");
        putAll(values, parseArgs(args), "command line");
        return new AppConfig(values);
    }

    public String get(String key, String fallback) {
        return values.getOrDefault(key, fallback);
    }

    /** An integer setting; a missing or malformed value gives the fallback (and a log line). */
    public int getInt(String key, int fallback) {
        String text = values.get(key);
        if (text == null) {
            return fallback;
        }
        try {
            return Integer.parseInt(text.trim());
        } catch (NumberFormatException e) {
            LOG.warning("Setting " + key + " is not a number (" + text + "), using " + fallback);
            return fallback;
        }
    }

    /** A duration setting given in minutes. */
    public Duration getMinutes(String key, int fallbackMinutes) {
        return Duration.ofMinutes(getInt(key, fallbackMinutes));
    }

    /** The data folder: --data.dir / AEGISLENS_DATA_DIR / data.dir in the file, else ~/.aegislens. */
    public AppPaths paths() {
        String dir = values.get(DATA_DIR);
        return dir == null ? AppPaths.defaultPaths() : new AppPaths(Path.of(dir));
    }

    private static void putAll(Map<String, String> target, Map<String, String> source, String origin) {
        for (Map.Entry<String, String> e : source.entrySet()) {
            if (isSecret(e.getKey())) {
                LOG.warning("Ignoring secret-looking setting '" + e.getKey() + "' from the " + origin
                        + ": API keys are read only from their own environment variables");
            } else {
                target.put(e.getKey(), e.getValue());
            }
        }
    }

    /** True for names such as claude.api.key or splitshield.token, which never come from files or Settings. */
    static boolean isSecret(String key) {
        return SECRET.matcher(key).matches();
    }

    private static Map<String, String> readProperties(Path file) throws IOException {
        Map<String, String> result = new HashMap<>();
        if (file == null || !Files.isRegularFile(file)) {
            return result;
        }
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(file)) {
            props.load(in);
        }
        for (String key : props.stringPropertyNames()) {
            result.put(key, props.getProperty(key));
        }
        return result;
    }

    /** AEGISLENS_DEDUPE_COOLDOWN_MINUTES=5 becomes dedupe.cooldown.minutes=5. */
    private static Map<String, String> fromEnv(Map<String, String> env) {
        Map<String, String> result = new HashMap<>();
        for (Map.Entry<String, String> e : env.entrySet()) {
            if (e.getKey().startsWith(ENV_PREFIX)) {
                String key = e.getKey().substring(ENV_PREFIX.length()).toLowerCase(Locale.ROOT).replace('_', '.');
                result.put(key, e.getValue());
            }
        }
        return result;
    }

    /** --key=value pairs; anything else (for example JavaFX's own arguments) is ignored. */
    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> result = new HashMap<>();
        if (args == null) {
            return result;
        }
        for (String arg : args) {
            int eq = arg.indexOf('=');
            if (arg.startsWith("--") && eq > 2) {
                result.put(arg.substring(2, eq), arg.substring(eq + 1));
            }
        }
        return result;
    }
}
