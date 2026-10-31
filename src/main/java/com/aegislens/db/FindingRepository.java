package com.aegislens.db;

import com.aegislens.core.Finding;
import com.aegislens.core.Severity;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * CRUD, batching, paging and dashboard queries for findings, using plain JDBC and PreparedStatement (never string concatenation).
 * Thread-safe: writes go through Database.locked()/transaction(), reads through Database.read().
 * Evidence is stored as JSON text (a Map&lt;String, String&gt;); SQLite's json_extract can query inside it if ever needed.
 */
public class FindingRepository extends BaseRepository<Finding, Long> implements Repository<Finding, Long> {

    /** Upper bound for findAll(); the UI pages with findPage instead. */
    public static final int FIND_ALL_LIMIT = 10_000;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String INSERT = "INSERT INTO finding (session_id, source, target, rule_id, severity, score, description, "
            + "evidence, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    public FindingRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "finding";
    }

    /** Inserts the finding. It must already have a session id (see ScanSessionRepository.begin). */
    @Override
    public void save(Finding f) throws SQLException {
        checkSession(f);
        long id = db.locked(c -> insertOne(c, f));
        f.setId(id);
    }

    /** Inserts many findings in ONE transaction (one disk sync instead of one per row). All or nothing. */
    public void saveAll(List<Finding> findings) throws SQLException {
        for (Finding f : findings) {
            checkSession(f);
        }
        long[] ids = db.transaction(c -> {
            long[] result = new long[findings.size()];
            for (int i = 0; i < findings.size(); i++) {
                result[i] = insertOne(c, findings.get(i));
            }
            return result;
        });
        for (int i = 0; i < ids.length; i++) {
            findings.get(i).setId(ids[i]);
        }
    }

    private static void checkSession(Finding f) throws SQLException {
        if (f.sessionId() <= 0) {
            throw new SQLException("Finding has no session id: call setSessionId() first");
        }
    }

    private static long insertOne(Connection c, Finding f) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(INSERT)) {
            ps.setLong(1, f.sessionId());
            ps.setString(2, f.source());
            ps.setString(3, f.target());
            ps.setString(4, f.ruleId());
            ps.setString(5, f.severity().name());
            ps.setInt(6, f.score());
            ps.setString(7, f.description());
            ps.setString(8, toJson(f));
            ps.setString(9, f.status());
            ps.setString(10, iso(f.timestamp()));
            ps.executeUpdate();
        }
        return Database.lastInsertId(c);
    }

    @Override
    public Optional<Finding> findById(Long id) throws SQLException {
        return queryOne("SELECT * FROM finding WHERE id = ?", ps -> ps.setLong(1, id), FindingRepository::map);
    }

    /** The newest FIND_ALL_LIMIT findings. Not for the UI: use findPage, which never loads the whole table. */
    @Override
    public List<Finding> findAll() throws SQLException {
        return findRecent(FIND_ALL_LIMIT);
    }

    /** The newest findings (at most limit), newest first. */
    public List<Finding> findRecent(int limit) throws SQLException {
        return findPage(Long.MAX_VALUE, limit);
    }

    /**
     * One page of findings older than beforeId, newest first (keyset paging: fast on any page, unlike OFFSET).
     * First page: beforeId = Long.MAX_VALUE; next page: the id of the last row you got.
     */
    public List<Finding> findPage(long beforeId, int limit) throws SQLException {
        return queryList("SELECT * FROM finding WHERE id < ? ORDER BY id DESC LIMIT ?", ps -> {
            ps.setLong(1, beforeId);
            ps.setInt(2, limit);
        }, FindingRepository::map);
    }

    /** The newest findings about one target (an address or a file path). */
    public List<Finding> findByTarget(String target, int limit) throws SQLException {
        return queryList("SELECT * FROM finding WHERE target = ? ORDER BY created_at DESC LIMIT ?", ps -> {
            ps.setString(1, target);
            ps.setInt(2, limit);
        }, FindingRepository::map);
    }

    /** Recent findings of one rule, newest first (uses idx_finding_rule_stats). */
    public List<Finding> findByRule(String ruleId, int limit) throws SQLException {
        return queryList("SELECT * FROM finding WHERE rule_id = ? ORDER BY created_at DESC LIMIT ?", ps -> {
            ps.setString(1, ruleId);
            ps.setInt(2, limit);
        }, FindingRepository::map);
    }

    /** Number of findings with this status (OPEN, FALSE_POSITIVE or RESOLVED). */
    public int count(String status) throws SQLException {
        return queryOne("SELECT COUNT(*) FROM finding WHERE status = ?", ps -> ps.setString(1, status), rs -> rs.getInt(1)).orElse(0);
    }

    /** status is OPEN, FALSE_POSITIVE or RESOLVED. */
    public void updateStatus(long id, String status) throws SQLException {
        update("UPDATE finding SET status = ? WHERE id = ?", ps -> {
            ps.setString(1, status);
            ps.setLong(2, id);
        });
    }

    @Override
    public void delete(Long id) throws SQLException {
        update("DELETE FROM finding WHERE id = ?", ps -> ps.setLong(1, id));
    }

    /** D8: sets the status of many findings in ONE transaction (a batch); all or nothing. Returns rows changed. */
    public int updateStatusMany(Collection<Long> ids, String status) throws SQLException {
        return batchById("UPDATE finding SET status = ? WHERE id = ?", ids, status);
    }

    /** D8: deletes many findings in ONE transaction (a batch); all or nothing. Returns rows deleted. */
    public int deleteMany(Collection<Long> ids) throws SQLException {
        return batchById("DELETE FROM finding WHERE id = ?", ids, null);
    }

    /**
     * D8: marks every OPEN finding for this target as a false positive in one statement, so later reports and the
     * dashboard ignore it. Returns how many findings changed.
     */
    public int markTargetFalsePositive(String target) throws SQLException {
        return update("UPDATE finding SET status = 'FALSE_POSITIVE' WHERE target = ? AND status = 'OPEN'",
                ps -> ps.setString(1, target));
    }

    /** One prepared statement, one addBatch per id, executed inside a transaction. A non-null status is bound first. */
    private int batchById(String sql, Collection<Long> ids, String status) throws SQLException {
        if (ids.isEmpty()) {
            return 0;
        }
        return db.transaction(c -> {
            try (PreparedStatement ps = c.prepareStatement(sql)) {
                for (Long id : ids) {
                    int i = 1;
                    if (status != null) {
                        ps.setString(i++, status);
                    }
                    ps.setLong(i, id);
                    ps.addBatch();
                }
                int changed = 0;
                for (int n : ps.executeBatch()) {
                    changed += Math.max(n, 0);
                }
                return changed;
            }
        });
    }

    /**
     * Dashboard query. Since schema v3 it reads finding_counts (at most 15 rows, kept exact by triggers on finding)
     * instead of counting the whole table, so it stays fast with millions of findings.
     */
    static final String COUNT_BY_SEVERITY_SQL =
            "SELECT severity, SUM(n) FROM finding_counts WHERE status <> 'FALSE_POSITIVE' GROUP BY severity";

    /** Number of findings per severity (every severity present, zero if none). Excludes false positives. */
    public Map<Severity, Integer> countBySeverity() throws SQLException {
        Map<Severity, Integer> counts = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            counts.put(s, 0);
        }
        List<Map.Entry<String, Integer>> rows = queryList(COUNT_BY_SEVERITY_SQL, NO_PARAMS,
                rs -> Map.entry(rs.getString(1), rs.getInt(2)));
        for (Map.Entry<String, Integer> row : rows) {
            counts.put(Severity.valueOf(row.getKey()), row.getValue());
        }
        return counts;
    }

    /** One bucket of the timeline: an hour ("2026-10-29T14", UTC), a severity and how many findings. */
    public record HourCount(String hour, Severity severity, int count) {
    }

    /**
     * Findings per UTC hour and severity since the given time (false positives excluded), for the 24 h timeline.
     * created_at is ISO text, so its first 13 characters are the hour; idx_finding_time serves the range and covers the columns.
     * A unary + on a column ("+status") tells SQLite not to use an index on it, so it picks the covering index we want.
     */
    public List<HourCount> countByHourSince(Instant since) throws SQLException {
        return queryList("SELECT substr(created_at, 1, 13) AS hour, severity, COUNT(*) FROM finding "
                + "WHERE created_at >= ? AND +status IN ('OPEN', 'RESOLVED') GROUP BY hour, severity ORDER BY hour",
                ps -> ps.setString(1, iso(since)),
                rs -> new HourCount(rs.getString(1), Severity.valueOf(rs.getString(2)), rs.getInt(3)));
    }

    /**
     * Number of findings per module (MALWARE, INTRUSION, WEB, SANDBOX, HOST), excluding false positives. Counts per session
     * first (from idx_finding_session_stats alone), then JOINs the few sessions: 67 ms instead of 888 ms on 1 M rows.
     */
    public Map<String, Integer> countByModule() throws SQLException {
        Map<String, Integer> counts = new java.util.TreeMap<>();
        for (Map.Entry<String, Integer> row : queryList("SELECT s.module, SUM(c.n) FROM (SELECT session_id, COUNT(*) AS n "
                + "FROM finding WHERE +status IN ('OPEN', 'RESOLVED') GROUP BY session_id) c "
                + "JOIN scan_session s ON s.id = c.session_id GROUP BY s.module",
                NO_PARAMS, rs -> Map.entry(rs.getString(1), rs.getInt(2)))) {
            counts.put(row.getKey(), row.getValue());
        }
        return counts;
    }

    /** One target (an IP, a file path or a URL) and how many findings it has. */
    public record TargetCount(String target, int count) {
    }

    /** The targets with the most findings, excluding false positives (idx_finding_target_stats only: 165 ms on 1 M rows). */
    public List<TargetCount> topTargets(int limit) throws SQLException {
        return queryList("SELECT f.target, COUNT(*) AS n FROM finding f WHERE +f.status IN ('OPEN', 'RESOLVED') "
                + "AND +f.session_id IN (SELECT id FROM scan_session WHERE module IN ('INTRUSION', 'WEB')) "
                + "GROUP BY f.target ORDER BY n DESC, f.target LIMIT ?",
                ps -> ps.setInt(1, limit), rs -> new TargetCount(rs.getString(1), rs.getInt(2)));
    }

    private static String toJson(Finding f) throws SQLException {
        try {
            return JSON.writeValueAsString(f.evidence());
        } catch (JsonProcessingException e) {
            throw new SQLException("Could not serialise evidence", e);
        }
    }

    private static Finding map(ResultSet rs) throws SQLException {
        Map<String, String> evidence;
        try {
            String json = rs.getString("evidence");
            evidence = json == null ? Map.of() : JSON.readValue(json, new TypeReference<Map<String, String>>() { });
        } catch (JsonProcessingException e) {
            throw new SQLException("Corrupt evidence JSON", e);
        }
        Finding f = new Finding(rs.getString("source"), rs.getString("target"), rs.getString("rule_id"),
                rs.getInt("score"), rs.getString("description"), evidence, Instant.parse(rs.getString("created_at")));
        f.setId(rs.getLong("id"));
        f.setSessionId(rs.getLong("session_id"));
        f.setStatus(rs.getString("status"));
        return f;
    }
}
