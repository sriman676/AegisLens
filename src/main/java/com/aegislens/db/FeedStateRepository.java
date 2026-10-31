package com.aegislens.db;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

/**
 * Stores the state of each threat-intelligence feed so refreshes can use conditional requests and the UI can show
 * when each feed last worked.
 */
public class FeedStateRepository extends BaseRepository<FeedState, String> {

    public FeedStateRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "feed_state";
    }

    public Optional<FeedState> get(String name) throws SQLException {
        return queryOne("SELECT * FROM feed_state WHERE name = ?", ps -> ps.setString(1, name), FeedStateRepository::map);
    }

    /** Inserts or replaces the state of one feed. */
    public void save(FeedState s) throws SQLException {
        update("INSERT INTO feed_state (name, url, last_checked, last_success, etag, last_modified, entries, last_error) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET url = excluded.url, "
                + "last_checked = excluded.last_checked, last_success = excluded.last_success, etag = excluded.etag, "
                + "last_modified = excluded.last_modified, entries = excluded.entries, last_error = excluded.last_error", ps -> {
            ps.setString(1, s.name());
            ps.setString(2, s.url());
            ps.setString(3, iso(s.lastChecked()));
            ps.setString(4, iso(s.lastSuccess()));
            ps.setString(5, s.etag());
            ps.setString(6, s.lastModified());
            ps.setInt(7, s.entries());
            ps.setString(8, s.lastError());
        });
    }

    /** Every feed, sorted by name. */
    public List<FeedState> all() throws SQLException {
        return queryList("SELECT * FROM feed_state ORDER BY name", NO_PARAMS, FeedStateRepository::map);
    }

    private static FeedState map(ResultSet rs) throws SQLException {
        return new FeedState(rs.getString("name"), rs.getString("url"), instant(rs, "last_checked"),
                instant(rs, "last_success"), rs.getString("etag"), rs.getString("last_modified"),
                rs.getInt("entries"), rs.getString("last_error"));
    }
}
