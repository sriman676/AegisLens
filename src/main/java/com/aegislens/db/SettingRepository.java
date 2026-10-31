package com.aegislens.db;

import java.sql.SQLException;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Simple key/value application settings (thresholds, retention days, UI choices).
 * Secrets are never stored here: API keys come only from environment variables, so keys that look like
 * a secret are refused.
 */
public class SettingRepository extends BaseRepository<String, String> {

    private static final Pattern SECRET_KEY = Pattern.compile("(?i).*(api[_.-]?key|secret|token|password|passwd).*");

    public SettingRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "setting";
    }

    public Optional<String> get(String key) throws SQLException {
        return queryOne("SELECT value FROM setting WHERE key = ?", ps -> ps.setString(1, key), rs -> rs.getString(1));
    }

    public String getOrDefault(String key, String fallback) throws SQLException {
        return get(key).orElse(fallback);
    }

    /** Stores or replaces a setting. Throws IllegalArgumentException for keys that look like secrets. */
    public void put(String key, String value) throws SQLException {
        if (SECRET_KEY.matcher(key).matches()) {
            throw new IllegalArgumentException("Secrets are not stored in the database; use an environment variable: " + key);
        }
        update("INSERT INTO setting (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", ps -> {
            ps.setString(1, key);
            ps.setString(2, value);
        });
    }

    /** All settings, sorted by key. */
    public Map<String, String> all() throws SQLException {
        Map<String, String> result = new TreeMap<>();
        for (Map.Entry<String, String> e : queryList("SELECT key, value FROM setting", NO_PARAMS,
                rs -> Map.entry(rs.getString(1), rs.getString(2)))) {
            result.put(e.getKey(), e.getValue());
        }
        return result;
    }
}
