package com.aegislens.db;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Indicators of compromise (bad hashes, IPs, CIDR ranges, domains, URLs, strings, API names), loaded by hand or from feeds.
 * SQL is the source of truth; detectors keep an in-memory copy (values(kind)) for fast lookups.
 */
public class IocRepository extends BaseRepository<String, Long> {

    /** The kinds allowed by the CHECK constraint in schema.sql. */
    public static final Set<String> KINDS = Set.of("HASH", "IP", "CIDR", "DOMAIN", "URL", "STRING", "API");

    public IocRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "ioc";
    }

    /** Adds many values of one kind in ONE transaction; duplicates are ignored. Returns how many rows were new. */
    public int addAll(String kind, Collection<String> values, String source) throws SQLException {
        checkKind(kind);
        return db.transaction(c -> {
            int added = 0;
            try (PreparedStatement ps = c.prepareStatement("INSERT OR IGNORE INTO ioc (kind, value, source) VALUES (?, ?, ?)")) {
                for (String value : values) {
                    ps.setString(1, kind);
                    ps.setString(2, value);
                    ps.setString(3, source);
                    added += ps.executeUpdate();     // 0 when the row already existed
                }
            }
            return added;
        });
    }

    /**
     * Replaces everything a source (a feed) provided with a new list, in ONE transaction: either the new list is fully
     * in place or the old one is untouched. Returns how many values are now stored for that source.
     */
    public int replaceSource(String kind, String source, Collection<String> values) throws SQLException {
        checkKind(kind);
        return db.transaction(c -> {
            deleteBySource(source);                  // joins this transaction (nest-safe)
            addAll(kind, values, source);
            return queryCount(source);
        });
    }

    private int queryCount(String source) throws SQLException {
        return db.locked(c -> {
            try (PreparedStatement ps = c.prepareStatement("SELECT COUNT(*) FROM ioc WHERE source = ?")) {
                ps.setString(1, source);
                try (var rs = ps.executeQuery()) {
                    rs.next();
                    return rs.getInt(1);
                }
            }
        });
    }

    /** Removes every entry that came from one source (for example before re-importing a feed). Returns how many were removed. */
    public int deleteBySource(String source) throws SQLException {
        return update("DELETE FROM ioc WHERE source = ?", ps -> ps.setString(1, source));
    }

    public boolean exists(String kind, String value) throws SQLException {
        return queryOne("SELECT 1 FROM ioc WHERE kind = ? AND value = ?", ps -> {
            ps.setString(1, kind);
            ps.setString(2, value);
        }, rs -> Boolean.TRUE).isPresent();
    }

    /** All values of one kind, for an in-memory lookup set. */
    public Set<String> values(String kind) throws SQLException {
        return new HashSet<>(queryList("SELECT value FROM ioc WHERE kind = ?", ps -> ps.setString(1, kind), rs -> rs.getString(1)));
    }

    /** All values of one kind with the source they came from (value -> source), e.g. to tell C2 feeds apart. */
    public Map<String, String> valuesBySource(String kind) throws SQLException {
        Map<String, String> result = new HashMap<>();
        for (Map.Entry<String, String> e : queryList("SELECT value, source FROM ioc WHERE kind = ?", ps -> ps.setString(1, kind),
                rs -> Map.entry(rs.getString(1), rs.getString(2)))) {
            result.put(e.getKey(), e.getValue());
        }
        return result;
    }

    /** Number of entries per kind (kinds with no entries are left out). */
    public Map<String, Integer> countByKind() throws SQLException {
        Map<String, Integer> counts = new HashMap<>();
        for (Map.Entry<String, Integer> e : queryList("SELECT kind, COUNT(*) FROM ioc GROUP BY kind", NO_PARAMS,
                rs -> Map.entry(rs.getString(1), rs.getInt(2)))) {
            counts.put(e.getKey(), e.getValue());
        }
        return counts;
    }

    /** One stored indicator, for the list of your own entries. */
    public record IocEntry(long id, String kind, String value, String source, String note, String addedAt) {
    }

    /** Adds one indicator with a note; false if it was already there. */
    public boolean add(String kind, String value, String source, String note) throws SQLException {
        checkKind(kind);
        return update("INSERT OR IGNORE INTO ioc (kind, value, source, note) VALUES (?, ?, ?, ?)", ps -> {
            ps.setString(1, kind);
            ps.setString(2, value);
            ps.setString(3, source);
            ps.setString(4, note);
        }) == 1;
    }

    /** Entries from the given sources (for example your own "manual" ones), newest first. */
    public List<IocEntry> findBySources(String first, String second) throws SQLException {
        return queryList("SELECT id, kind, value, source, note, added_at FROM ioc WHERE source IN (?, ?) ORDER BY id DESC",
                ps -> {
                    ps.setString(1, first);
                    ps.setString(2, second);
                }, rs -> new IocEntry(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5),
                        rs.getString(6)));
    }

    /** Deletes one entry, but only if it came from one of the given sources (feeds stay untouched). */
    public boolean deleteById(long id, String first, String second) throws SQLException {
        return update("DELETE FROM ioc WHERE id = ? AND source IN (?, ?)", ps -> {
            ps.setLong(1, id);
            ps.setString(2, first);
            ps.setString(3, second);
        }) == 1;
    }

    private static void checkKind(String kind) {
        if (!KINDS.contains(kind)) {
            throw new IllegalArgumentException("Unknown IOC kind: " + kind);
        }
    }
}
