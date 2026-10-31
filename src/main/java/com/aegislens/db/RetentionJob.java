package com.aegislens.db;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Keeps the database from growing forever: deletes old RESOLVED and FALSE_POSITIVE findings (OPEN ones are
 * never aged out: an analyst still has to look at them), then finished sessions left with nothing in them, then old
 * audit rows. It also checkpoints the WAL,
 * lets SQLite refresh its statistics, and VACUUMs only when a lot of space is free. Run it once a day while the
 * monitor is idle (the daily schedule is wired in R2). Retention days can be changed in the setting table.
 */
public final class RetentionJob {

    public static final int DEFAULT_FINDING_DAYS = 90;
    public static final int DEFAULT_AUDIT_DAYS = 365;
    /** VACUUM only when more than this share of the pages is free. */
    public static final double VACUUM_FREE_RATIO = 0.20;
    public static final String FINDING_DAYS_SETTING = "retention.findings.days";
    public static final String AUDIT_DAYS_SETTING = "retention.audit.days";

    /** What one run did. */
    public record Result(int findingsDeleted, int sessionsDeleted, int auditDeleted, boolean vacuumed, long sizeBytes) {
    }

    private final Database db;
    /** Only closed findings age out; OPEN ones stay until an analyst resolves or dismisses them. */
    private static final String OLD_CLOSED_FINDINGS =
            "DELETE FROM finding WHERE created_at < ? AND status IN ('RESOLVED', 'FALSE_POSITIVE')";

    /**
     * Finished sessions with no findings and no file reports left. finished_at is written by SQLite's datetime('now')
     * ("2026-10-29 12:00:00"), so the ISO cutoff is converted to that form in SQL before comparing.
     */
    private static final String EMPTY_FINISHED_SESSIONS = "DELETE FROM scan_session WHERE status <> 'RUNNING' "
            + "AND finished_at < datetime(?) "
            + "AND NOT EXISTS (SELECT 1 FROM finding f WHERE f.session_id = scan_session.id) "
            + "AND NOT EXISTS (SELECT 1 FROM file_report r WHERE r.session_id = scan_session.id)";

    private final SettingRepository settings;

    public RetentionJob(Database db) {
        this.db = db;
        this.settings = new SettingRepository(db);
    }

    /** Runs every step once. now is a parameter so tests can travel in time. */
    public Result runOnce(Instant now) throws SQLException {
        int findingDays = days(FINDING_DAYS_SETTING, DEFAULT_FINDING_DAYS);
        int findings = deleteOlderThan(OLD_CLOSED_FINDINGS, now, findingDays);
        int sessions = deleteOlderThan(EMPTY_FINISHED_SESSIONS, now, findingDays);
        int audit = deleteOlderThan("DELETE FROM audit_log WHERE at < ?", now, days(AUDIT_DAYS_SETTING, DEFAULT_AUDIT_DAYS));
        pragma("PRAGMA wal_checkpoint(TRUNCATE)");
        pragma("PRAGMA optimize");
        boolean vacuumed = freeRatio() > VACUUM_FREE_RATIO;
        if (vacuumed) {
            pragma("VACUUM");
        }
        return new Result(findings, sessions, audit, vacuumed, sizeBytes());
    }

    /** Current database size in bytes (page count times page size). */
    public long sizeBytes() throws SQLException {
        return pragmaLong("PRAGMA page_count") * pragmaLong("PRAGMA page_size");
    }

    /** Share of pages that are free (0.0 to 1.0). */
    public double freeRatio() throws SQLException {
        long pages = pragmaLong("PRAGMA page_count");
        return pages == 0 ? 0.0 : (double) pragmaLong("PRAGMA freelist_count") / pages;
    }

    private int days(String key, int fallback) throws SQLException {
        try {
            int days = Integer.parseInt(settings.getOrDefault(key, String.valueOf(fallback)));
            return days > 0 ? days : fallback;
        } catch (NumberFormatException e) {
            return fallback;                // a bad setting must not stop the clean-up
        }
    }

    /** Timestamps are ISO-8601 UTC text, so a string comparison is a time comparison (to the second). */
    private int deleteOlderThan(String sql, Instant now, int days) throws SQLException {
        String cutoff = now.minus(Duration.ofDays(days)).truncatedTo(ChronoUnit.SECONDS).toString();
        return db.locked(c -> {
            try (PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setString(1, cutoff);
                return ps.executeUpdate();
            }
        });
    }

    private void pragma(String sql) throws SQLException {
        db.locked(c -> {
            try (Statement st = c.createStatement()) {
                st.execute(sql);
            }
            return null;
        });
    }

    private long pragmaLong(String sql) throws SQLException {
        return db.locked(c -> {
            try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery(sql)) {
                return rs.next() ? rs.getLong(1) : 0L;
            }
        });
    }
}
