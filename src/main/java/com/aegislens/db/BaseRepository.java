package com.aegislens.db;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Common parent of the repositories: holds the Database and offers small helpers so every subclass uses
 * PreparedStatement, reads through db.read() and writes through db.locked().
 * T is the entity type and ID its key type.
 */
public abstract class BaseRepository<T, ID> {

    /** Fills the ? placeholders of a statement. */
    @FunctionalInterface
    protected interface Binder {
        void bind(PreparedStatement ps) throws SQLException;
    }

    /** Turns the current row of a ResultSet into an object. */
    @FunctionalInterface
    protected interface RowMapper<R> {
        R map(ResultSet rs) throws SQLException;
    }

    /** For statements without placeholders. */
    protected static final Binder NO_PARAMS = ps -> { };

    protected final Database db;

    protected BaseRepository(Database db) {
        this.db = db;
    }

    /** Table name for count(). Must be a constant from our own code, never user input. */
    protected abstract String tableName();

    /** Number of rows in the table. */
    public int count() throws SQLException {
        return queryOne("SELECT COUNT(*) FROM " + tableName(), NO_PARAMS, rs -> rs.getInt(1)).orElse(0);
    }

    /** Runs a SELECT on the reader and maps every row. The ResultSet never leaves the lock. */
    protected <R> List<R> queryList(String sql, Binder binder, RowMapper<R> mapper) throws SQLException {
        return db.read(c -> {
            List<R> result = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement(sql)) {
                binder.bind(ps);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        result.add(mapper.map(rs));
                    }
                }
            }
            return result;
        });
    }

    /** Runs a SELECT on the reader and maps the first row, if any. */
    protected <R> Optional<R> queryOne(String sql, Binder binder, RowMapper<R> mapper) throws SQLException {
        List<R> rows = queryList(sql, binder, mapper);
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
    }

    /** Runs an INSERT, UPDATE or DELETE on the writer and returns the number of changed rows. */
    protected int update(String sql, Binder binder) throws SQLException {
        return db.locked(c -> {
            try (PreparedStatement ps = c.prepareStatement(sql)) {
                binder.bind(ps);
                return ps.executeUpdate();
            }
        });
    }

    /** Runs an INSERT on the writer and returns the new row id (never getGeneratedKeys, see Database.lastInsertId). */
    protected long insert(String sql, Binder binder) throws SQLException {
        return db.locked(c -> {
            try (PreparedStatement ps = c.prepareStatement(sql)) {
                binder.bind(ps);
                ps.executeUpdate();
            }
            return Database.lastInsertId(c);
        });
    }

    /** Timestamps are always stored as UTC ISO-8601 text ending in Z (Instant.toString), so they sort correctly. */
    protected static String iso(Instant instant) {
        return instant == null ? null : instant.toString();
    }

    /** Reads a timestamp column written by iso(); null stays null. */
    protected static Instant instant(ResultSet rs, String column) throws SQLException {
        String text = rs.getString(column);
        return text == null ? null : Instant.parse(text);
    }
}
