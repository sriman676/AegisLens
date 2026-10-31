package com.aegislens.db;

import java.time.Instant;

/**
 * Summary of one statically analysed file: where it was, its type, size, hashes, entropy and overall risk score.
 * id is 0 until the report is saved.
 */
public record FileReport(long id, long sessionId, String path, String fileType, long sizeBytes, String md5,
                         String sha256, double entropy, int riskScore, Instant scannedAt) {

    /** A new, not yet saved report for the given session. */
    public FileReport(long sessionId, String path, String fileType, long sizeBytes, String md5, String sha256,
                      double entropy, int riskScore) {
        this(0, sessionId, path, fileType, sizeBytes, md5, sha256, entropy, riskScore, Instant.now());
    }
}
