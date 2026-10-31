package com.aegislens.db;

import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Optional;

/**
 * Remembers where each tailed log file stopped, so a restart continues instead of re-reading (and re-alerting).
 * Paths are stored absolute and normalised, which works on every operating system.
 */
public class LogOffsetRepository extends BaseRepository<LogOffset, String> {

    public LogOffsetRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "log_offset";
    }

    public Optional<LogOffset> get(Path file) throws SQLException {
        return queryOne("SELECT * FROM log_offset WHERE path = ?", ps -> ps.setString(1, key(file)),
                rs -> new LogOffset(rs.getString("path"), rs.getLong("offset"), rs.getString("fingerprint"),
                        instant(rs, "updated_at")));
    }

    public void put(Path file, long offset, String fingerprint) throws SQLException {
        if (offset < 0) {
            throw new IllegalArgumentException("offset must not be negative: " + offset);
        }
        update("INSERT INTO log_offset (path, \"offset\", fingerprint, updated_at) VALUES (?, ?, ?, ?) "
                + "ON CONFLICT(path) DO UPDATE SET \"offset\" = excluded.\"offset\", fingerprint = excluded.fingerprint, "
                + "updated_at = excluded.updated_at", ps -> {
            ps.setString(1, key(file));
            ps.setLong(2, offset);
            ps.setString(3, fingerprint);
            ps.setString(4, iso(Instant.now()));
        });
    }

    private static String key(Path file) {
        return file.toAbsolutePath().normalize().toString();
    }
}
