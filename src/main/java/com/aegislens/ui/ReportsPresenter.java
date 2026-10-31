package com.aegislens.ui;

import com.aegislens.db.ReportRepository;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Logic of the Reports and SQL views, kept out of JavaFX so it is unit-tested: fills the per-day chart with every day
 * (days without findings show as 0, not as a gap) and holds the example queries offered in the SQL console.
 */
public final class ReportsPresenter {

    /** Days shown in the per-day chart. */
    public static final int DAYS = 14;
    /** Example queries for the SQL console (name -> SQL). Every one is a read-only SELECT on our own schema. */
    public static final Map<String, String> EXAMPLES = examples();

    private ReportsPresenter() {
    }

    /**
     * severity -> (day -> count) for the last {@code days} days, every day present, oldest first. Severities go LOW to
     * CRITICAL so series 0..3 get the same colours as the dashboard (default-color0 = LOW in both stylesheets).
     */
    public static Map<String, Map<String, Integer>> series(List<ReportRepository.DayCount> rows, int days, Instant now) {
        Map<String, Map<String, Integer>> series = new LinkedHashMap<>();
        for (String severity : List.of("LOW", "MEDIUM", "HIGH", "CRITICAL")) {
            Map<String, Integer> perDay = new LinkedHashMap<>();
            for (int i = days - 1; i >= 0; i--) {
                perDay.put(now.truncatedTo(ChronoUnit.DAYS).minus(i, ChronoUnit.DAYS).toString().substring(0, 10), 0);
            }
            series.put(severity, perDay);
        }
        for (ReportRepository.DayCount row : rows) {
            Map<String, Integer> perDay = series.get(row.severity());
            if (perDay != null && perDay.containsKey(row.day())) {
                perDay.put(row.day(), row.count());
            }
        }
        return series;
    }

    /** "2026-10-30" -> "10-30" for the chart's axis. */
    public static String shortDay(String day) {
        return day.length() == 10 ? day.substring(5) : day;
    }

    private static Map<String, String> examples() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("Newest findings with module (view)",
                "SELECT id, created_at, severity, rule_id, module, target FROM v_finding_detail ORDER BY id DESC LIMIT 50");
        m.put("Findings per rule (GROUP BY + HAVING)",
                "SELECT rule_id, COUNT(*) AS n, MAX(score) AS top FROM finding GROUP BY rule_id HAVING COUNT(*) > 1 ORDER BY n DESC");
        m.put("Targets on an IOC list (subquery)",
                "SELECT target, COUNT(*) AS n FROM finding WHERE target IN (SELECT value FROM ioc) GROUP BY target");
        m.put("Dashboard counts (trigger-maintained table)",
                "SELECT severity, status, n FROM finding_counts ORDER BY severity, status");
        m.put("Audit trail written by the trigger",
                "SELECT at, detail FROM audit_log WHERE actor = 'trigger' ORDER BY id DESC LIMIT 50");
        m.put("Query plan (EXPLAIN)",
                "EXPLAIN QUERY PLAN SELECT * FROM finding WHERE rule_id = 'NET-001' ORDER BY created_at DESC");
        m.put("Threat-intel entries per feed",
                "SELECT source, kind, COUNT(*) AS n FROM ioc GROUP BY source, kind ORDER BY n DESC");
        return m;
    }
}
