package com.aegislens.db;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * Read-only reports for the Reports view: JOINs over the v_finding_detail view (D3), GROUP BY with HAVING (D4),
 * subqueries (D5) and the EXPLAIN QUERY PLAN of each report (D12). False positives are left out of every report.
 */
public class ReportRepository extends BaseRepository<ReportRepository.DetailRow, Long> {

    /** One finding with its context: rule name, module, newest AI explanation (or null) and whether its target is an IOC. */
    public record DetailRow(long id, String createdAt, String severity, int score, String ruleId, String ruleName,
                            String module, String target, String description, String status, String explanation,
                            boolean iocHit) {
    }

    /** Findings of one day and severity. Day is "YYYY-MM-DD" (UTC). */
    public record DayCount(String day, String severity, int count) {
    }

    /** One rule: how often it fired and its highest score. */
    public record RuleCount(String ruleId, String ruleName, int count, int maxScore) {
    }

    /** How many findings one module has at one severity (for the Findings explorer tree). */
    public record ModuleCount(String module, String severity, int count) {
    }

    /** One target (an IP for intrusion findings) with its number of findings and first/last time seen. */
    public record TargetStats(String target, int count, int maxScore, String firstSeen, String lastSeen) {
    }

    /** Every report's SQL, kept in one place so the Reports view can show its query plan (D12). */
    public enum Query {
        /** D3: view JOIN newest explanation, EXISTS for the IOC check. */
        WITH_CONTEXT("SELECT d.id, d.created_at, d.severity, d.score, d.rule_id, d.rule_name, d.module, d.target, "
                + "d.description, d.status, a.explanation, "
                + "EXISTS (SELECT 1 FROM ioc i WHERE i.value = d.target) AS ioc_hit "
                + "FROM v_finding_detail d "
                + "LEFT JOIN ai_explanation a ON a.id = (SELECT x.id FROM ai_explanation x WHERE x.finding_id = d.id "
                + "ORDER BY x.created_at DESC, x.id DESC LIMIT 1) "
                + "WHERE d.status <> 'FALSE_POSITIVE' ORDER BY d.id DESC LIMIT ?"),
        /** D2 + D4: the daily view, grouped again by day and severity. */
        PER_DAY("SELECT day, severity, SUM(n) FROM v_daily_counts WHERE day >= ? AND status <> 'FALSE_POSITIVE' "
                + "GROUP BY day, severity ORDER BY day, severity"),
        /** D4: GROUP BY with HAVING. */
        PER_RULE("SELECT f.rule_id, COALESCE(r.name, f.rule_id), COUNT(*) AS n, MAX(f.score) FROM finding f "
                + "LEFT JOIN rule r ON r.id = f.rule_id WHERE f.status <> 'FALSE_POSITIVE' "
                + "GROUP BY f.rule_id HAVING COUNT(*) >= ? ORDER BY n DESC, f.rule_id"),
        /**
         * D4 + D5: aggregates per attacker (intrusion findings only, IN subquery). The unary + keeps SQLite on the covering
         * index idx_finding_target_stats (rows already grouped by target): 0.2 s instead of 3.5 s on 1 M findings.
         */
        TOP_ATTACKERS("SELECT f.target, COUNT(*) AS n, MAX(f.score), MIN(f.created_at), MAX(f.created_at) FROM finding f "
                + "WHERE f.status <> 'FALSE_POSITIVE' "
                + "AND +f.session_id IN (SELECT id FROM scan_session WHERE module = 'INTRUSION') "
                + "GROUP BY f.target ORDER BY n DESC, f.target LIMIT ?"),
        /** D4: module x severity, for the explorer tree: counted per session from the covering index, then JOINed. */
        PER_MODULE_SEVERITY("SELECT s.module, c.severity, SUM(c.n) FROM (SELECT session_id, severity, COUNT(*) AS n "
                + "FROM finding WHERE status <> 'FALSE_POSITIVE' GROUP BY session_id, severity) c "
                + "JOIN scan_session s ON s.id = c.session_id GROUP BY s.module, c.severity ORDER BY s.module, c.severity"),
        /** D5: a subquery in FROM (a derived table) filtered by its own aggregate. */
        TARGETS_WITH_MORE_THAN("SELECT t.target, t.n, t.top, t.first_seen, t.last_seen FROM "
                + "(SELECT target, COUNT(*) AS n, MAX(score) AS top, MIN(created_at) AS first_seen, "
                + "MAX(created_at) AS last_seen FROM finding WHERE status <> 'FALSE_POSITIVE' GROUP BY target) t "
                + "WHERE t.n > ? ORDER BY t.n DESC, t.target"),
        /** D5: an IN subquery against the threat-intelligence table. */
        IOC_TARGETS("SELECT f.target, COUNT(*) AS n, MAX(f.score), MIN(f.created_at), MAX(f.created_at) FROM finding f "
                + "WHERE f.status <> 'FALSE_POSITIVE' AND f.target IN (SELECT i.value FROM ioc i) "
                + "GROUP BY f.target ORDER BY n DESC, f.target");

        private final String sql;
        private final String plan;

        Query(String sql) {
            this.sql = sql;
            this.plan = "EXPLAIN QUERY PLAN " + sql;    // both parts are constants from this enum, never input
        }

        /** The SQL text (a constant from our code, shown in the Reports view). */
        public String sql() {
            return sql;
        }
    }

    public ReportRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "finding";
    }

    /** D3: the newest findings with their context, newest first. */
    public List<DetailRow> findingsWithContext(int limit) throws SQLException {
        return queryList(Query.WITH_CONTEXT.sql(), ps -> ps.setInt(1, limit), ReportRepository::detail);
    }

    /** D4: findings per day and severity for the last {@code days} days (today included). */
    public List<DayCount> perDay(int days, Instant now) throws SQLException {
        String firstDay = now.truncatedTo(ChronoUnit.DAYS).minus(days - 1L, ChronoUnit.DAYS).toString().substring(0, 10);
        return queryList(Query.PER_DAY.sql(), ps -> ps.setString(1, firstDay),
                rs -> new DayCount(rs.getString(1), rs.getString(2), rs.getInt(3)));
    }

    /** D4: rules that fired at least {@code minCount} times (HAVING), most frequent first. */
    public List<RuleCount> perRule(int minCount) throws SQLException {
        return queryList(Query.PER_RULE.sql(), ps -> ps.setInt(1, minCount),
                rs -> new RuleCount(rs.getString(1), rs.getString(2), rs.getInt(3), rs.getInt(4)));
    }

    /** D4: findings per module and severity (false positives left out). */
    public List<ModuleCount> perModuleAndSeverity() throws SQLException {
        return queryList(Query.PER_MODULE_SEVERITY.sql(), NO_PARAMS,
                rs -> new ModuleCount(rs.getString(1), rs.getString(2), rs.getInt(3)));
    }

    /** D4: the {@code n} intrusion targets with the most findings. */
    public List<TargetStats> topAttackers(int n) throws SQLException {
        return queryList(Query.TOP_ATTACKERS.sql(), ps -> ps.setInt(1, n), ReportRepository::targetStats);
    }

    /** D5: targets with more than {@code n} findings (derived-table subquery). */
    public List<TargetStats> targetsWithMoreThan(int n) throws SQLException {
        return queryList(Query.TARGETS_WITH_MORE_THAN.sql(), ps -> ps.setInt(1, n), ReportRepository::targetStats);
    }

    /** D5: targets that appear on an IOC list (IN subquery). */
    public List<TargetStats> findingsWithIocTarget() throws SQLException {
        return queryList(Query.IOC_TARGETS.sql(), NO_PARAMS, ReportRepository::targetStats);
    }

    /** D12: the query plan SQLite chooses for a report, one step per line ("SEARCH ... USING INDEX ..."). */
    public String explain(Query query) throws SQLException {
        return db.read(c -> {
            List<String> steps = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement(query.plan);
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    steps.add(rs.getString("detail"));
                }
            }
            return String.join("\n", steps);
        });
    }

    /** Maps the 12 columns of WITH_CONTEXT (FindingSearch selects the same columns). */
    static DetailRow detail(ResultSet rs) throws SQLException {
        return new DetailRow(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getInt(4), rs.getString(5),
                rs.getString(6), rs.getString(7), rs.getString(8), rs.getString(9), rs.getString(10),
                rs.getString(11), rs.getInt(12) == 1);
    }

    private static TargetStats targetStats(ResultSet rs) throws SQLException {
        return new TargetStats(rs.getString(1), rs.getInt(2), rs.getInt(3), rs.getString(4), rs.getString(5));
    }
}
