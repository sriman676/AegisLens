package com.aegislens.core;

/**
 * Anything that has a 0-100 risk score.
 */
public interface Scorable {

    /** Risk score from 0 (harmless) to 100 (critical). */
    int score();

    /** Severity derived from the score. */
    default Severity severity() {
        return Severity.fromScore(score());
    }
}
