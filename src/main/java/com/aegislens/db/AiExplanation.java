package com.aegislens.db;

import java.time.Instant;

/** The explanation one AI provider (cloud, local model or offline templates) gave for one finding. */
public record AiExplanation(long findingId, String provider, String explanation, Instant createdAt) {
}
