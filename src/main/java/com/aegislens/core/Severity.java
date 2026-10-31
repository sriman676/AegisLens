package com.aegislens.core;

/**
 * How serious a finding is. Derived from the 0-100 score (README: Detection rules).
 */
public enum Severity {
    LOW(0), MEDIUM(30), HIGH(60), CRITICAL(85);

    private final int minScore;

    Severity(int minScore) {
        this.minScore = minScore;
    }

    public int minScore() {
        return minScore;
    }

    /** Maps a 0-100 score to a severity: 0-29 LOW, 30-59 MEDIUM, 60-84 HIGH, 85-100 CRITICAL. */
    public static Severity fromScore(int score) {
        if (score < 0 || score > 100) {
            throw new IllegalArgumentException("score must be 0-100 but was " + score);
        }
        Severity result = LOW;
        for (Severity s : values()) {
            if (score >= s.minScore) {
                result = s;
            }
        }
        return result;
    }
}
