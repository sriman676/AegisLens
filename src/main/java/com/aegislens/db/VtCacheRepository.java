package com.aegislens.db;

import java.sql.SQLException;
import java.util.Optional;

/**
 * Caches VirusTotal hash lookups so the user's limited free API quota is not spent on the same file twice.
 */
public class VtCacheRepository extends BaseRepository<VtResult, String> {

    public VtCacheRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "vt_cache";
    }

    public Optional<VtResult> find(String sha256) throws SQLException {
        return queryOne("SELECT * FROM vt_cache WHERE sha256 = ?", ps -> ps.setString(1, sha256),
                rs -> new VtResult(rs.getString("sha256"), rs.getInt("known") == 1, rs.getInt("malicious"),
                        rs.getInt("suspicious"), rs.getInt("total"), instant(rs, "checked_at")));
    }

    public void save(VtResult r) throws SQLException {
        update("INSERT INTO vt_cache (sha256, known, malicious, suspicious, total, checked_at) VALUES (?, ?, ?, ?, ?, ?) "
                + "ON CONFLICT(sha256) DO UPDATE SET known = excluded.known, malicious = excluded.malicious, "
                + "suspicious = excluded.suspicious, total = excluded.total, checked_at = excluded.checked_at", ps -> {
            ps.setString(1, r.sha256());
            ps.setInt(2, r.known() ? 1 : 0);
            ps.setInt(3, r.malicious());
            ps.setInt(4, r.suspicious());
            ps.setInt(5, r.total());
            ps.setString(6, iso(r.checkedAt()));
        });
    }
}
