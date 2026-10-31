package com.aegislens.db;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

/**
 * Stores one report per analysed file and finds earlier scans of the same file by SHA-256.
 */
public class FileReportRepository extends BaseRepository<FileReport, Long> implements Repository<FileReport, Long> {

    /** Upper bound for findAll(); the UI uses findRecent with a small limit. */
    public static final int FIND_ALL_LIMIT = 10_000;

    public FileReportRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "file_report";
    }

    /** Saves the report under its own session id. */
    @Override
    public void save(FileReport report) throws SQLException {
        save(report, report.sessionId());
    }

    /** Saves the report under the given session and returns the new id. */
    public long save(FileReport r, long sessionId) throws SQLException {
        if (r.riskScore() < 0 || r.riskScore() > 100) {
            throw new IllegalArgumentException("risk score must be 0-100 but was " + r.riskScore());
        }
        return insert("INSERT INTO file_report (session_id, path, file_type, size_bytes, md5, sha256, entropy, risk_score, scanned_at) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", ps -> {
            ps.setLong(1, sessionId);
            ps.setString(2, r.path());
            ps.setString(3, r.fileType());
            ps.setLong(4, r.sizeBytes());
            ps.setString(5, r.md5());
            ps.setString(6, r.sha256());
            ps.setDouble(7, r.entropy());
            ps.setInt(8, r.riskScore());
            ps.setString(9, iso(r.scannedAt()));
        });
    }

    @Override
    public Optional<FileReport> findById(Long id) throws SQLException {
        return queryOne("SELECT * FROM file_report WHERE id = ?", ps -> ps.setLong(1, id), FileReportRepository::map);
    }

    /** Every earlier scan of the file with this SHA-256, newest first. */
    public List<FileReport> findBySha256(String sha256) throws SQLException {
        return queryList("SELECT * FROM file_report WHERE sha256 = ? ORDER BY id DESC", ps -> ps.setString(1, sha256),
                FileReportRepository::map);
    }

    /** The newest reports, newest first. */
    public List<FileReport> findRecent(int limit) throws SQLException {
        return queryList("SELECT * FROM file_report ORDER BY id DESC LIMIT ?", ps -> ps.setInt(1, limit), FileReportRepository::map);
    }

    /** The newest FIND_ALL_LIMIT reports (never an unbounded table load). */
    @Override
    public List<FileReport> findAll() throws SQLException {
        return findRecent(FIND_ALL_LIMIT);
    }

    @Override
    public void delete(Long id) throws SQLException {
        update("DELETE FROM file_report WHERE id = ?", ps -> ps.setLong(1, id));
    }

    private static FileReport map(ResultSet rs) throws SQLException {
        return new FileReport(rs.getLong("id"), rs.getLong("session_id"), rs.getString("path"), rs.getString("file_type"),
                rs.getLong("size_bytes"), rs.getString("md5"), rs.getString("sha256"), rs.getDouble("entropy"),
                rs.getInt("risk_score"), instant(rs, "scanned_at"));
    }
}
