package com.aegislens.app;

import com.aegislens.db.RuleDef;
import com.aegislens.db.RuleRepository;
import com.aegislens.malware.FileAnalyzer;
import com.aegislens.malware.MalwareRules;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

/**
 * A snapshot of the rule table for the malware scanner. reload() swaps in a new snapshot after Settings changed a rule,
 * so the next scan uses it; a rule missing from the table counts as switched on with its the README rule table default.
 */
final class LiveRules implements MalwareRules {

    private volatile Map<String, RuleDef> rules = Map.of();

    void reload(RuleRepository repo) throws SQLException {
        Map<String, RuleDef> fresh = new HashMap<>();
        for (RuleDef r : repo.findAll()) {
            fresh.put(r.id(), r);
        }
        rules = Map.copyOf(fresh);
    }

    @Override
    public boolean enabled(String ruleId) {
        RuleDef r = rules.get(ruleId);
        return r == null || r.enabled();
    }

    @Override
    public double entropyThreshold() {
        return threshold("MAL-001", FileAnalyzer.PACKED_ENTROPY);
    }

    /** The pattern of a rule (for example WEB-002's SQL-injection pattern), or fallback when it has none. */
    String pattern(String ruleId, String fallback) {
        RuleDef r = rules.get(ruleId);
        return r == null || r.pattern() == null || r.pattern().isBlank() ? fallback : r.pattern();
    }

    /** The threshold of a rule, or fallback when the rule has none. */
    double threshold(String ruleId, double fallback) {
        RuleDef r = rules.get(ruleId);
        return r == null || r.threshold() == null ? fallback : r.threshold();
    }
}
