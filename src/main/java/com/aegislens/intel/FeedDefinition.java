package com.aegislens.intel;

import java.net.URI;
import java.time.Duration;

/**
 * One threat-intelligence feed as configured in feeds.properties: where to download it, how to read it, what kind of
 * indicator it holds, how often to check, an optional auth header (value from an environment variable), whether an
 * empty list is normal, whether hits mean botnet C2 (score 90), and the attribution its terms require.
 */
public record FeedDefinition(String name, URI url, String format, String kind, boolean enabled, Duration interval,
                             Duration minInterval, String headerName, String headerEnv, boolean allowEmpty, boolean c2,
                             String field, String attribution) {

    /** The source name stored with each IOC; IntrusionSetup treats sources containing "c2" or "feodo" as C2 lists. */
    public String source() {
        return c2 && !name.contains("c2") ? name + "-c2" : name;
    }
}
