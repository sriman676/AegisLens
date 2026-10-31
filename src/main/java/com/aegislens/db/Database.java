package com.aegislens.db;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

/**
 * Owns the SQLite connections, creates or upgrades the tables, and makes access thread-safe.
 * A file database has two connections: a writer (inserts, updates, transactions) and a read-only reader
 * (UI queries), each guarded by its own lock, so WAL lets readers run while the writer is busy.
 * An in-memory database has one connection and one lock (a second ":memory:" connection would be a different database).
 * Lock order: a thread may call read() while holding the write lock, never the other way round.
 */
public final class Database implements AutoCloseable {

    /** Bump when schema.sql changes in a way old files cannot absorb; add a step to {@link #migrate(Connection, int)}. */
    public static final int SCHEMA_VERSION = 5;

    /** A piece of JDBC work that returns a value. */
    @FunctionalInterface
    public interface SqlWork<R> {
        R run(Connection connection) throws SQLException;
    }

    private final Connection writer;
    private final Connection reader;
    private final Object writeLock = new Object();
    private final Object readLock;
    private final boolean ftsAvailable;
    private int transactionDepth;          // guarded by writeLock

    private Database(Connection writer, Connection reader, boolean ftsAvailable) {
        this.writer = writer;
        this.reader = reader;
        this.ftsAvailable = ftsAvailable;
        this.readLock = (reader == writer) ? writeLock : new Object();
    }

    /** Opens any JDBC URL, for example "jdbc:sqlite:aegislens.db". */
    public static Database open(String jdbcUrl) throws SQLException {
        try {
            Class.forName("org.sqlite.JDBC");      // register the driver explicitly (also safe inside a fat JAR)
        } catch (ClassNotFoundException e) {
            throw new SQLException("SQLite JDBC driver is missing from the classpath", e);
        }
        boolean fileBased = !jdbcUrl.contains(":memory:");
        Connection writer = DriverManager.getConnection(jdbcUrl);
        try {
            configureWriter(writer, fileBased);
            boolean fts = initSchema(writer);
            Connection reader = fileBased ? openReader(jdbcUrl) : writer;
            return new Database(writer, reader, fts);
        } catch (SQLException | RuntimeException e) {
            writer.close();
            throw e;
        }
    }

    /** Opens (or creates) a database file, creating the parent folder. Path works on every operating system. */
    public static Database open(Path file) throws SQLException {
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (IOException e) {
            throw new SQLException("Cannot create database folder for " + file, e);
        }
        return open("jdbc:sqlite:" + file.toAbsolutePath());
    }

    /** A throw-away database in memory, used by tests. */
    public static Database inMemory() throws SQLException {
        return open("jdbc:sqlite::memory:");
    }

    private static void configureWriter(Connection c, boolean fileBased) throws SQLException {
        try (Statement st = c.createStatement()) {
            st.execute("PRAGMA foreign_keys = ON");        // SQLite needs this on every connection
            st.execute("PRAGMA busy_timeout = 5000");      // wait up to 5 s if another process holds the file
            if (fileBased) {
                st.execute("PRAGMA journal_mode = WAL");
                st.execute("PRAGMA synchronous = NORMAL");
            }
        }
    }

    private static Connection openReader(String jdbcUrl) throws SQLException {
        Connection c = DriverManager.getConnection(jdbcUrl);
        try (Statement st = c.createStatement()) {
            st.execute("PRAGMA busy_timeout = 5000");
            st.execute("PRAGMA query_only = ON");          // any write on the reader fails
        } catch (SQLException e) {
            c.close();
            throw e;
        }
        return c;
    }

    /** Raw writer connection. NOT thread-safe: use only inside locked() or transaction(), or in single-threaded tests. */
    public Connection connection() {
        return writer;
    }

    /** True when this database has a separate read-only connection (file databases). */
    public boolean hasSeparateReader() {
        return reader != writer;
    }

    /** Runs write work on the writer connection while holding the write lock. */
    public <R> R locked(SqlWork<R> work) throws SQLException {
        if (hasSeparateReader() && Thread.holdsLock(readLock)) {
            throw new IllegalStateException("Do not write while holding the read lock (lock order: write, then read)");
        }
        synchronized (writeLock) {
            return work.run(writer);
        }
    }

    /**
     * Runs read-only work on the reader connection. Readers see committed data only, so inside a transaction
     * use the Connection that transaction() gives you instead.
     */
    public <R> R read(SqlWork<R> work) throws SQLException {
        synchronized (readLock) {
            return work.run(reader);
        }
    }

    /**
     * Runs work in one transaction (all or nothing) on the writer. Nest-safe: a transaction() inside another one
     * joins the outer transaction, and only the outermost call commits or rolls back. If inner work throws and the
     * outer work does not catch it, everything is rolled back.
     */
    public <R> R transaction(SqlWork<R> work) throws SQLException {
        return locked(c -> {
            if (transactionDepth > 0) {
                return runNested(work);
            }
            return runOutermost(work);
        });
    }

    private <R> R runNested(SqlWork<R> work) throws SQLException {
        transactionDepth++;
        try {
            return work.run(writer);
        } finally {
            transactionDepth--;
        }
    }

    private <R> R runOutermost(SqlWork<R> work) throws SQLException {
        writer.setAutoCommit(false);
        transactionDepth = 1;
        try {
            R result = work.run(writer);
            writer.commit();
            return result;
        } catch (SQLException | RuntimeException e) {
            writer.rollback();
            throw e;
        } finally {
            transactionDepth = 0;
            writer.setAutoCommit(true);
        }
    }

    /** Id of the row inserted last on this connection. Call inside locked()/transaction(). The driver's getGeneratedKeys is not portable. */
    public static long lastInsertId(Connection c) throws SQLException {
        try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("SELECT last_insert_rowid()")) {
            rs.next();
            return rs.getLong(1);
        }
    }

    public int schemaVersion() throws SQLException {
        return locked(Database::userVersion);
    }

    private static int userVersion(Connection c) throws SQLException {
        try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("PRAGMA user_version")) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    /**
     * Brings the file to SCHEMA_VERSION. Existing files are migrated BEFORE the create script, so the script's
     * indexes can rely on columns that a migration adds. A brand-new file reports version 0 and only runs the script.
     */
    private static boolean initSchema(Connection c) throws SQLException {
        int existing = userVersion(c);
        if (existing > SCHEMA_VERSION) {
            throw new SQLException("Database file has schema version " + existing + ", newer than this app (" + SCHEMA_VERSION + ")");
        }
        if (existing > 0 && existing < SCHEMA_VERSION) {
            migrate(c, existing);
        }
        try (Statement st = c.createStatement()) {
            for (String statement : readStatements("/schema.sql")) {
                st.execute(statement);
            }
            if (existing < SCHEMA_VERSION) {
                st.execute("PRAGMA user_version = " + SCHEMA_VERSION);   // a constant from our code, never input
            }
        }
        return initFullText(c, existing > 0 && existing < 3);
    }

    /** True when the FTS5 search index exists; otherwise text search falls back to LIKE. */
    public boolean ftsAvailable() {
        return ftsAvailable;
    }

    /**
     * Optional full-text search (schema-fts.sql). Returns false if this SQLite build has no FTS5; search then uses LIKE.
     * After an upgrade the index is rebuilt from the existing findings.
     */
    private static boolean initFullText(Connection c, boolean rebuild) {
        try (Statement st = c.createStatement()) {
            for (String statement : readStatements("/schema-fts.sql")) {
                st.execute(statement);
            }
            if (rebuild) {
                st.execute("INSERT INTO finding_fts (finding_fts) VALUES ('rebuild')");
            }
            return true;
        } catch (SQLException noFts5) {
            return false;
        }
    }

    /**
     * Upgrades an older file one version at a time. The cases fall through on purpose: a version-1 file runs
     * step 1 and then every later step. Each step runs in its own transaction.
     */
    private static void migrate(Connection c, int fromVersion) throws SQLException {
        switch (fromVersion) {
            case 1:
                inTransaction(c, Database::migrate1To2);
                // fall through
            case 2:
                inTransaction(c, Database::migrate2To3);
                // fall through
            case 3:
                inTransaction(c, Database::migrate3To4);
                // fall through
            case 4:
                withoutForeignKeys(c, Database::migrate4To5);
                // fall through: later steps go here as "case 5:", "case 6:" ...
            default:
                break;
        }
    }

    /**
     * Version 3 adds finding_counts, kept up to date by triggers. An upgraded file already has findings, so the table
     * is created and filled here, BEFORE the create script adds the triggers (otherwise rows would be counted twice).
     */
    private static void migrate2To3(Connection c) throws SQLException {
        if (!tableExists(c, "finding")) {
            return;
        }
        try (Statement st = c.createStatement()) {
            st.execute("CREATE TABLE IF NOT EXISTS finding_counts (severity TEXT NOT NULL, status TEXT NOT NULL, "
                    + "n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (severity, status))");
            st.execute("DELETE FROM finding_counts");
            st.execute("INSERT INTO finding_counts (severity, status, n) SELECT severity, status, COUNT(*) FROM finding GROUP BY severity, status");
        }
    }

    /** Version 4 replaces four narrow finding indexes with covering ones; the create script then adds the new ones. */
    private static void migrate3To4(Connection c) throws SQLException {
        try (Statement st = c.createStatement()) {
            for (String drop : List.of("DROP INDEX IF EXISTS idx_finding_target", "DROP INDEX IF EXISTS idx_finding_created",
                    "DROP INDEX IF EXISTS idx_finding_rule", "DROP INDEX IF EXISTS idx_finding_session")) {
                st.execute(drop);
            }
        }
    }

    /**
     * Version 5 adds the HOST module (Sysmon findings). SQLite cannot change a CHECK constraint, so scan_session is
     * rebuilt: new table, copy, drop, rename (the documented "12-step" way). The view that reads it is dropped first
     * and made again by the create script, which also makes the delete-guard trigger again.
     */
    private static void migrate4To5(Connection c) throws SQLException {
        if (!tableExists(c, "scan_session")) {
            return;
        }
        try (Statement st = c.createStatement()) {
            st.execute("DROP VIEW IF EXISTS v_finding_detail");
            st.execute("CREATE TABLE scan_session_v5 (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    + "module TEXT NOT NULL CHECK (module IN ('MALWARE','INTRUSION','WEB','SANDBOX','HOST')), "
                    + "started_at TEXT NOT NULL DEFAULT (datetime('now')), finished_at TEXT, target TEXT NOT NULL, "
                    + "status TEXT NOT NULL DEFAULT 'RUNNING' CHECK (status IN ('RUNNING','DONE','FAILED')))");
            st.execute("INSERT INTO scan_session_v5 (id, module, started_at, finished_at, target, status) "
                    + "SELECT id, module, started_at, finished_at, target, status FROM scan_session");
            st.execute("DROP TABLE scan_session");
            st.execute("ALTER TABLE scan_session_v5 RENAME TO scan_session");
        }
    }

    /**
     * Runs a step with foreign keys off (dropping a parent table with them on would cascade-delete every finding), then
     * checks that every reference still points to a row before switching them back on. The PRAGMA does nothing inside
     * a transaction, so it is set around the step's own transaction.
     */
    private static void withoutForeignKeys(Connection c, MigrationStep step) throws SQLException {
        try (Statement st = c.createStatement()) {
            st.execute("PRAGMA foreign_keys = OFF");
            try {
                inTransaction(c, step);
                try (ResultSet broken = st.executeQuery("PRAGMA foreign_key_check")) {
                    if (broken.next()) {
                        throw new SQLException("migration left a broken reference in table " + broken.getString(1));
                    }
                }
            } finally {
                st.execute("PRAGMA foreign_keys = ON");
            }
        }
    }

    /** Version 1 had no finding.status column; version 2 needs it (and indexes on it). */
    private static void migrate1To2(Connection c) throws SQLException {
        if (tableExists(c, "finding") && !columnExists(c, "finding", "status")) {
            try (Statement st = c.createStatement()) {
                st.execute("ALTER TABLE finding ADD COLUMN status TEXT NOT NULL DEFAULT 'OPEN' "
                        + "CHECK (status IN ('OPEN','FALSE_POSITIVE','RESOLVED'))");
            }
        }
    }

    @FunctionalInterface
    private interface MigrationStep {
        void apply(Connection c) throws SQLException;
    }

    private static void inTransaction(Connection c, MigrationStep step) throws SQLException {
        c.setAutoCommit(false);
        try {
            step.apply(c);
            c.commit();
        } catch (SQLException | RuntimeException e) {
            c.rollback();
            throw e;
        } finally {
            c.setAutoCommit(true);
        }
    }

    private static boolean tableExists(Connection c, String table) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")) {
            ps.setString(1, table);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private static boolean columnExists(Connection c, String table, String column) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("SELECT 1 FROM pragma_table_info(?) WHERE name = ?")) {
            ps.setString(1, table);
            ps.setString(2, column);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /** The line that ends a statement in schema files (so a trigger body with ';' inside stays one statement). */
    static final String SEPARATOR = "-- GO";

    /**
     * The statements of a schema resource: split at lines that are exactly "-- GO"; other whole-line "--" comments are
     * dropped. Package-private so a test can check the rules.
     */
    static List<String> readStatements(String resource) throws SQLException {
        try (InputStream in = Database.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new SQLException(resource + " not found on the classpath");
            }
            List<String> statements = new java.util.ArrayList<>();
            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String t = line.trim();
                    if (t.equals(SEPARATOR)) {
                        if (!sb.toString().isBlank()) {
                            statements.add(sb.toString().strip());
                        }
                        sb.setLength(0);
                    } else if (!t.startsWith("--")) {
                        sb.append(line).append('\n');
                    }
                }
            }
            if (!sb.toString().isBlank()) {
                throw new SQLException(resource + " ends without a \"" + SEPARATOR + "\" line after its last statement");
            }
            return statements;
        } catch (IOException e) {
            throw new SQLException("Could not read " + resource, e);
        }
    }

    @Override
    public void close() throws SQLException {
        synchronized (writeLock) {
            try {
                if (hasSeparateReader()) {
                    synchronized (readLock) {
                        reader.close();
                    }
                }
            } finally {
                writer.close();
            }
        }
    }
}
