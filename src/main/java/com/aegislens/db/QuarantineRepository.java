package com.aegislens.db;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Records of quarantined files. This class only stores the record; moving the file itself is done elsewhere.
 */
public class QuarantineRepository extends BaseRepository<QuarantineEntry, Long> implements Repository<QuarantineEntry, Long> {

    public QuarantineRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "quarantine";
    }

    /** Records a newly quarantined file and returns its id. */
    public long add(String originalPath, String vaultPath, String sha256, String reason) throws SQLException {
        return insert("INSERT INTO quarantine (original_path, vault_path, sha256, reason, at) VALUES (?, ?, ?, ?, ?)", ps -> {
            ps.setString(1, originalPath);
            ps.setString(2, vaultPath);
            ps.setString(3, sha256);
            ps.setString(4, reason);
            ps.setString(5, iso(Instant.now()));
        });
    }

    @Override
    public void save(QuarantineEntry e) throws SQLException {
        add(e.originalPath(), e.vaultPath(), e.sha256(), e.reason());
    }

    /** Same as findById, with the name used in R1. */
    public Optional<QuarantineEntry> find(long id) throws SQLException {
        return findById(id);
    }

    @Override
    public Optional<QuarantineEntry> findById(Long id) throws SQLException {
        return queryOne("SELECT * FROM quarantine WHERE id = ?", ps -> ps.setLong(1, id), QuarantineRepository::map);
    }

    /** Every quarantine record, newest first. */
    @Override
    public List<QuarantineEntry> findAll() throws SQLException {
        return queryList("SELECT * FROM quarantine ORDER BY id DESC", NO_PARAMS, QuarantineRepository::map);
    }

    /** Marks the file as restored. Returns false if no record has that id. */
    public boolean markRestored(long id) throws SQLException {
        return update("UPDATE quarantine SET restored = 1 WHERE id = ?", ps -> ps.setLong(1, id)) == 1;
    }

    @Override
    public void delete(Long id) throws SQLException {
        update("DELETE FROM quarantine WHERE id = ?", ps -> ps.setLong(1, id));
    }

    private static QuarantineEntry map(ResultSet rs) throws SQLException {
        return new QuarantineEntry(rs.getLong("id"), rs.getString("original_path"), rs.getString("vault_path"),
                rs.getString("sha256"), rs.getString("reason"), instant(rs, "at"), rs.getInt("restored") == 1);
    }
}
