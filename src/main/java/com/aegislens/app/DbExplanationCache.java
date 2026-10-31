package com.aegislens.app;

import com.aegislens.ai.ExplanationCache;
import com.aegislens.db.AiExplanation;
import com.aegislens.db.AiExplanationRepository;

import java.sql.SQLException;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The explanation cache kept in the ai_explanation table (one answer per finding and provider), so an answer that was
 * paid for once is reused, also after a restart. Database errors only mean "not cached".
 */
public final class DbExplanationCache implements ExplanationCache {

    private static final Logger LOG = Logger.getLogger(DbExplanationCache.class.getName());

    private final AiExplanationRepository repo;

    public DbExplanationCache(AiExplanationRepository repo) {
        this.repo = repo;
    }

    @Override
    public Optional<String> find(long findingId, String provider) {
        try {
            return repo.find(findingId, provider).map(AiExplanation::explanation);
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Explanation cache read failed", e);
            return Optional.empty();
        }
    }

    @Override
    public void store(long findingId, String provider, String text) {
        try {
            repo.save(findingId, provider, text);
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Explanation cache write failed", e);
        }
    }
}
