package com.aegislens.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Read-only SQL console for the SQL view (D13): the analyst may run ONE SELECT, WITH or EXPLAIN statement. Three layers
 * keep it read-only: (1) the text check below, (2) the reader connection is opened with PRAGMA query_only, so SQLite
 * itself refuses writes, (3) results are capped at {@link #MAX_ROWS} rows and {@link #TIMEOUT_SECONDS} seconds.
 * This is the only class that runs SQL typed by a person; it never runs it on the writer connection.
 */
public final class SqlConsole {

    /** Most rows shown; the result says when there were more. */
    public static final int MAX_ROWS = 500;
    /** A query running longer than this is cancelled. */
    public static final int TIMEOUT_SECONDS = 5;
    /** Longest statement accepted (characters). */
    public static final int MAX_LENGTH = 10_000;

    private static final Set<String> ALLOWED_FIRST_WORDS = Set.of("SELECT", "WITH", "EXPLAIN");
    /** Words that have no place in a read-only query, even inside a WITH. */
    private static final Pattern FORBIDDEN = Pattern.compile(
            "\\b(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|ANALYZE|"
                    + "LOAD_EXTENSION|BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)\\b");

    /** The answer: column names, rows as text (null stays null), whether rows were cut off, and the run time. */
    public record Result(List<String> columns, List<List<String>> rows, boolean truncated, long millis) {
    }

    /** Thrown when a statement is refused before it reaches the database. */
    public static final class RefusedException extends SQLException {
        RefusedException(String message) {
            super(message);
        }
    }

    private final Database db;

    public SqlConsole(Database db) {
        this.db = db;
    }

    /** Checks and runs one read-only statement. */
    public Result run(String text) throws SQLException {
        String sql = check(text);
        long start = System.nanoTime();
        return db.read(c -> {
            boolean wasReadOnly = queryOnly(c);
            setQueryOnly(c, true);                 // in-memory databases share the writer connection
            try {
                return execute(c, sql, start);
            } finally {
                setQueryOnly(c, wasReadOnly);      // a file database's reader stays read-only for good
            }
        });
    }

    /** Returns the statement without a trailing ';', or throws RefusedException with a reason the UI can show. */
    static String check(String text) throws RefusedException {
        if (text == null || text.isBlank()) {
            throw new RefusedException("Type a SELECT statement first.");
        }
        if (text.length() > MAX_LENGTH) {
            throw new RefusedException("Statement is longer than " + MAX_LENGTH + " characters.");
        }
        String sql = text.strip();
        while (sql.endsWith(";")) {
            sql = sql.substring(0, sql.length() - 1).strip();
        }
        if (sql.contains(";")) {
            throw new RefusedException("Only one statement at a time (remove the ';').");
        }
        if (sql.contains("--") || sql.contains("/*")) {
            throw new RefusedException("Comments are not allowed in the console.");
        }
        String upper = sql.toUpperCase(Locale.ROOT);
        String first = upper.split("\\s+", 2)[0];
        if (!ALLOWED_FIRST_WORDS.contains(first)) {
            throw new RefusedException("Read-only console: start with SELECT, WITH or EXPLAIN.");
        }
        var bad = FORBIDDEN.matcher(upper.replaceAll("'(?:[^']|'')*'", "''"));   // words inside string literals are fine
        if (bad.find()) {
            throw new RefusedException("Read-only console: " + bad.group(1) + " is not allowed.");
        }
        return sql;
    }

    private static Result execute(Connection c, String sql, long start) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setQueryTimeout(TIMEOUT_SECONDS);
            ps.setMaxRows(MAX_ROWS + 1);
            try (ResultSet rs = ps.executeQuery()) {
                ResultSetMetaData meta = rs.getMetaData();
                List<String> columns = new ArrayList<>();
                for (int i = 1; i <= meta.getColumnCount(); i++) {
                    columns.add(meta.getColumnLabel(i));
                }
                List<List<String>> rows = new ArrayList<>();
                boolean truncated = false;
                while (rs.next()) {
                    if (rows.size() == MAX_ROWS) {
                        truncated = true;
                        break;
                    }
                    List<String> row = new ArrayList<>();
                    for (int i = 1; i <= columns.size(); i++) {
                        row.add(rs.getString(i));
                    }
                    rows.add(row);
                }
                return new Result(columns, rows, truncated, (System.nanoTime() - start) / 1_000_000);
            }
        }
    }

    private static boolean queryOnly(Connection c) throws SQLException {
        try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("PRAGMA query_only")) {
            return rs.next() && rs.getInt(1) == 1;
        }
    }

    private static void setQueryOnly(Connection c, boolean on) throws SQLException {
        try (Statement st = c.createStatement()) {
            st.execute(on ? "PRAGMA query_only = 1" : "PRAGMA query_only = 0");
        }
    }
}
