package com.aegislens.db;

import java.time.Instant;

/**
 * A cached VirusTotal answer for one SHA-256: whether VirusTotal knows the file and how many engines flagged it
 * as malicious or suspicious out of the total.
 */
public record VtResult(String sha256, boolean known, int malicious, int suspicious, int total, Instant checkedAt) {
}
