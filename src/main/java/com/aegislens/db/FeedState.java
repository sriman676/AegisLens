package com.aegislens.db;

import java.time.Instant;

/**
 * Download state of one threat-intelligence feed: when it was last checked and last succeeded, the HTTP caching
 * headers (ETag, Last-Modified) for conditional requests, how many entries it gave, and the last error.
 */
public record FeedState(String name, String url, Instant lastChecked, Instant lastSuccess, String etag,
                        String lastModified, int entries, String lastError) {
}
