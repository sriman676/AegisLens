package com.aegislens.db;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Findings explorer search (D9): free text plus severity, status, module and date filters, newest first, paged with a
 * keyset ("findings older than id X") so page 500 is as fast as page 1. Text uses the FTS5 index when the SQLite build
 * has it, otherwise LIKE. The WHERE clause is assembled only from the fixed fragments below; every value is a ? parameter.
 */
public class FindingSearch {

    /** Most rows one page may ask for. */
    public static final int MAX_PAGE = 500;

    private static final String SELECT = "SELECT d.id, d.created_at, d.severity, d.score, d.rule_id, d.rule_name, d.module, "
            + "d.target, d.description, d.status, NULL AS explanation, EXISTS (SELECT 1 FROM ioc i WHERE i.value = d.target) "
            + "FROM v_finding_detail d WHERE 1 = 1";
    private static final String FTS_TEXT = " AND d.id IN (SELECT rowid FROM finding_fts WHERE finding_fts MATCH ?)";
    private static final String LIKE_TEXT = " AND (d.description LIKE ? ESCAPE '\\' OR d.target LIKE ? ESCAPE '\\')";

    /**
     * What to look for. Null or blank fields mean "any". {@code from} is inclusive, {@code to} exclusive.
     */
    public record Filter(String text, String severity, String status, String module, Instant from, Instant to) {

        /** No filter at all. */
        public static final Filter ALL = new Filter(null, null, null, null, null, null);
    }

    private final Database db;
    private final boolean useFts;

    /** Uses full-text search when this database has it. */
    public FindingSearch(Database db) {
        this(db, db.ftsAvailable());
    }

    /** Package-private so a test can force the LIKE fallback. */
    FindingSearch(Database db, boolean useFts) {
        this.db = db;
        this.useFts = useFts;
    }

    /** True when text search uses the FTS5 index. */
    public boolean fullText() {
        return useFts;
    }

    /**
     * One page of matches, newest first. Pass {@code beforeId = null} for the first page and the last row's id for the next.
     */
    public List<ReportRepository.DetailRow> search(Filter filter, Long beforeId, int limit) throws SQLException {
        StringBuilder sql = new StringBuilder(SELECT);
        List<Object> params = new ArrayList<>();
        addText(sql, params, filter.text());
        addEquals(sql, params, " AND d.severity = ?", filter.severity());
        addEquals(sql, params, " AND d.status = ?", filter.status());
        addEquals(sql, params, " AND d.module = ?", filter.module());
        if (filter.from() != null) {
            sql.append(" AND d.created_at >= ?");
            params.add(filter.from().toString());
        }
        if (filter.to() != null) {
            sql.append(" AND d.created_at < ?");
            params.add(filter.to().toString());
        }
        if (beforeId != null) {
            sql.append(" AND d.id < ?");
            params.add(beforeId);
        }
        sql.append(" ORDER BY d.id DESC LIMIT ?");
        params.add(Math.max(1, Math.min(limit, MAX_PAGE)));
        return run(sql.toString(), params);
    }

    private void addText(StringBuilder sql, List<Object> params, String text) {
        if (text == null || text.isBlank()) {
            return;
        }
        if (useFts) {
            sql.append(FTS_TEXT);
            params.add(ftsQuery(text));
        } else {
            for (String word : text.strip().split("\\s+")) {     // like FTS: every word must match
                sql.append(LIKE_TEXT);
                String pattern = "%" + escapeLike(word) + "%";
                params.add(pattern);
                params.add(pattern);
            }
        }
    }

    private static void addEquals(StringBuilder sql, List<Object> params, String fragment, String value) {
        if (value != null && !value.isBlank()) {
            sql.append(fragment);
            params.add(value.strip().toUpperCase(Locale.ROOT));
        }
    }

    private List<ReportRepository.DetailRow> run(String sql, List<Object> params) throws SQLException {
        return db.read(c -> {
            List<ReportRepository.DetailRow> rows = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement(sql)) {
                for (int i = 0; i < params.size(); i++) {
                    ps.setObject(i + 1, params.get(i));
                }
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        rows.add(ReportRepository.detail(rs));
                    }
                }
            }
            return rows;
        });
    }

    /**
     * Turns user text into a safe FTS5 query: every word becomes a quoted prefix term ("word"*), all words must match.
     * Quoting means FTS5 operators typed by the user (OR, NEAR, -, :) are searched as plain text, never interpreted.
     */
    static String ftsQuery(String text) {
        List<String> terms = new ArrayList<>();
        for (String word : text.strip().split("\\s+")) {
            terms.add("\"" + word.replace("\"", "\"\"") + "\"*");
        }
        return String.join(" ", terms);
    }

    /** Escapes the LIKE wildcards % and _ (and the escape character itself) so they match literally. */
    static String escapeLike(String text) {
        return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }
}
