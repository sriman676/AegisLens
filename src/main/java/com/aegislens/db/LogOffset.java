package com.aegislens.db;

import java.time.Instant;

/**
 * How far a log file has been read: byte offset plus a fingerprint of the file's first bytes, so a rotated
 * (replaced) file is detected and read from the start again.
 */
public record LogOffset(String path, long offset, String fingerprint, Instant updatedAt) {
}
