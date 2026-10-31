package com.aegislens.db;

import java.time.Instant;

/**
 * A file moved into the quarantine vault: where it came from, where it is stored, its hash, why, when, and whether it
 * has been restored. id is 0 until saved.
 */
public record QuarantineEntry(long id, String originalPath, String vaultPath, String sha256, String reason,
                              Instant at, boolean restored) {
}
