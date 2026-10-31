package com.aegislens.ai;

import java.util.Optional;

/**
 * Remembers AI answers per finding and provider, so the same finding is never sent (and paid for) twice.
 * The app implements it on top of the ai_explanation table; the ai package itself never touches the database.
 */
public interface ExplanationCache {

    Optional<String> find(long findingId, String provider);

    void store(long findingId, String provider, String text);

    /** No caching (tests, or findings that are not saved yet). */
    ExplanationCache NONE = new ExplanationCache() {
        @Override
        public Optional<String> find(long findingId, String provider) {
            return Optional.empty();
        }

        @Override
        public void store(long findingId, String provider, String text) {
            // nothing to remember
        }
    };
}
