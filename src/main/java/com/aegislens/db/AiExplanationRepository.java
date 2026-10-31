package com.aegislens.db;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Caches AI explanations per finding and provider, so the same finding is not sent to an LLM twice and answers
 * from different providers can be shown side by side.
 */
public class AiExplanationRepository extends BaseRepository<AiExplanation, Long> {

    public AiExplanationRepository(Database db) {
        super(db);
    }

    @Override
    protected String tableName() {
        return "ai_explanation";
    }

    public Optional<AiExplanation> find(long findingId, String provider) throws SQLException {
        return queryOne("SELECT * FROM ai_explanation WHERE finding_id = ? AND provider = ?", ps -> {
            ps.setLong(1, findingId);
            ps.setString(2, provider);
        }, AiExplanationRepository::map);
    }

    /** Every provider's explanation for one finding, oldest first. */
    public List<AiExplanation> findByFinding(long findingId) throws SQLException {
        return queryList("SELECT * FROM ai_explanation WHERE finding_id = ? ORDER BY created_at, provider",
                ps -> ps.setLong(1, findingId), AiExplanationRepository::map);
    }

    /** Stores the explanation; a newer answer from the same provider for the same finding replaces the old one. */
    public void save(long findingId, String provider, String explanation) throws SQLException {
        update("INSERT INTO ai_explanation (finding_id, provider, explanation, created_at) VALUES (?, ?, ?, ?) "
                + "ON CONFLICT(finding_id, provider) DO UPDATE SET explanation = excluded.explanation, created_at = excluded.created_at", ps -> {
            ps.setLong(1, findingId);
            ps.setString(2, provider);
            ps.setString(3, explanation);
            ps.setString(4, iso(Instant.now()));
        });
    }

    private static AiExplanation map(ResultSet rs) throws SQLException {
        return new AiExplanation(rs.getLong("finding_id"), rs.getString("provider"), rs.getString("explanation"),
                instant(rs, "created_at"));
    }
}
