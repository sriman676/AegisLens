package com.aegislens.core;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One security observation (for example "5 failed SSH logins from 203.0.113.45").
 * Shared by every module, so do not change its public API without telling the team.
 * Natural order = most severe first, so a TreeSet of findings is sorted automatically.
 */
public class Finding implements Scorable, Comparable<Finding> {

    private long id;          // set by the database after saving
    private long sessionId;   // which scan session produced it (set before saving)
    private String status = "OPEN";   // OPEN, FALSE_POSITIVE or RESOLVED (changed by the analyst)
    private final String source;
    private final String target;
    private final String ruleId;
    private final int score;
    private final String description;
    private final Map<String, String> evidence;
    private final Instant timestamp;

    /** Full constructor. */
    public Finding(String source, String target, String ruleId, int score,
                   String description, Map<String, String> evidence, Instant timestamp) {
        if (score < 0 || score > 100) {
            throw new IllegalArgumentException("score must be 0-100 but was " + score);
        }
        this.source = require(source, "source");
        this.target = require(target, "target");
        this.ruleId = require(ruleId, "ruleId");
        this.score = score;
        this.description = require(description, "description");
        this.evidence = evidence == null ? new LinkedHashMap<>() : new LinkedHashMap<>(evidence);
        this.timestamp = timestamp == null ? Instant.now() : timestamp;
    }

    /** Convenience constructor: no evidence, timestamp = now. */
    public Finding(String source, String target, String ruleId, int score, String description) {
        this(source, target, ruleId, score, description, null, null);
    }

    private static String require(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    public long id() { return id; }
    public void setId(long id) { this.id = id; }
    public long sessionId() { return sessionId; }
    public void setSessionId(long sessionId) { this.sessionId = sessionId; }
    public String status() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String source() { return source; }
    public String target() { return target; }
    public String ruleId() { return ruleId; }
    public String description() { return description; }
    public Instant timestamp() { return timestamp; }

    /** Read-only view of the evidence. */
    public Map<String, String> evidence() { return Collections.unmodifiableMap(evidence); }

    @Override
    public int score() { return score; }

    @Override
    public int compareTo(Finding other) {
        int c = other.severity().compareTo(this.severity());       // higher severity first
        if (c != 0) return c;
        c = Integer.compare(other.score, this.score);               // higher score first
        if (c != 0) return c;
        c = this.timestamp.compareTo(other.timestamp);              // older first
        if (c != 0) return c;
        c = this.ruleId.compareTo(other.ruleId);
        if (c != 0) return c;
        return this.target.compareTo(other.target);
    }

    @Override
    public String toString() {
        return severity() + " [" + ruleId + "] " + target + " (score " + score + "): " + description;
    }
}
