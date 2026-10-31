package com.aegislens.db;

import java.time.Instant;

/** An IP address the analyst decided to block, with the reason and time. The app only records and exports it. */
public record BlockedIp(String ip, String reason, Instant blockedAt) {
}
