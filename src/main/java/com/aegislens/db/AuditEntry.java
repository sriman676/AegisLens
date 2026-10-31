package com.aegislens.db;

import java.time.Instant;

/** One line of the audit trail: who did what, with optional detail, and when. */
public record AuditEntry(long id, String actor, String action, String detail, Instant at) {
}
