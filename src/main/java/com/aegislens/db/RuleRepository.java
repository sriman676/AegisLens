package com.aegislens.db;

import com.aegislens.core.Severity;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;
import java.util.Optional;

/**
 * Detection rules and their thresholds, editable at run time (the seed rows come from schema.sql).
 */
public class RuleRepository extends BaseRepository<RuleDef, String> implements Repository<RuleDef, String> {

    private static final String UPSERT = "INSERT INTO rule (id, module, name, pattern, threshold, severity, enabled) "
            + "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET module = excluded.module, name = excluded.name, "
            + "pattern = excluded.pattern, threshold = excluded.threshold, severity = excluded.severity, enabled = excluded.enabled";

    public RuleRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "rule";
    }

    /** Inserts the rule, or replaces the stored one with the same id. */
    @Override
    public void save(RuleDef rule) throws SQLException {
        update(UPSERT, ps -> {
            ps.setString(1, rule.id());
            ps.setString(2, rule.module());
            ps.setString(3, rule.name());
            ps.setString(4, rule.pattern());
            if (rule.threshold() == null) {
                ps.setNull(5, Types.REAL);
            } else {
                ps.setDouble(5, rule.threshold());
            }
            ps.setString(6, rule.severity().name());
            ps.setInt(7, rule.enabled() ? 1 : 0);
        });
    }

    @Override
    public Optional<RuleDef> findById(String id) throws SQLException {
        return queryOne("SELECT * FROM rule WHERE id = ?", ps -> ps.setString(1, id), RuleRepository::map);
    }

    @Override
    public List<RuleDef> findAll() throws SQLException {
        return queryList("SELECT * FROM rule ORDER BY id", NO_PARAMS, RuleRepository::map);
    }

    /** The enabled rules of one module (MALWARE, INTRUSION, WEB, SANDBOX, HOST). */
    public List<RuleDef> findEnabled(String module) throws SQLException {
        return queryList("SELECT * FROM rule WHERE module = ? AND enabled = 1 ORDER BY id",
                ps -> ps.setString(1, module), RuleRepository::map);
    }

    /** Switches a rule on or off. Returns false if no rule has that id. */
    public boolean setEnabled(String id, boolean enabled) throws SQLException {
        return update("UPDATE rule SET enabled = ? WHERE id = ?", ps -> {
            ps.setInt(1, enabled ? 1 : 0);
            ps.setString(2, id);
        }) == 1;
    }

    /** Changes a rule's threshold. Returns false if no rule has that id. */
    public boolean setThreshold(String id, double threshold) throws SQLException {
        return update("UPDATE rule SET threshold = ? WHERE id = ?", ps -> {
            ps.setDouble(1, threshold);
            ps.setString(2, id);
        }) == 1;
    }

    @Override
    public void delete(String id) throws SQLException {
        update("DELETE FROM rule WHERE id = ?", ps -> ps.setString(1, id));
    }

    private static RuleDef map(ResultSet rs) throws SQLException {
        double threshold = rs.getDouble("threshold");
        Double maybe = rs.wasNull() ? null : threshold;
        return new RuleDef(rs.getString("id"), rs.getString("module"), rs.getString("name"), rs.getString("pattern"),
                maybe, Severity.valueOf(rs.getString("severity")), rs.getInt("enabled") == 1);
    }
}
