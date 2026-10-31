package com.aegislens.intrusion;

import com.aegislens.core.Detector;
import com.aegislens.core.Finding;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Parent of every log detector: a Detector&lt;LogEvent&gt; with a fixed rule id and helpers to build findings and
 * keep a sliding time window. Detectors are stateful and used by one thread at a time (the tailer or the replay).
 */
public abstract class LogDetector implements Detector<LogEvent> {

    protected final String ruleId;

    protected LogDetector(String ruleId) {
        this.ruleId = ruleId;
    }

    public final String ruleId() {
        return ruleId;
    }

    /** A finding for this rule about event's IP (or the user if there is no IP). Evidence keeps its insertion order. */
    protected final Finding finding(LogEvent event, int score, String description, Map<String, String> evidence) {
        Map<String, String> ev = new LinkedHashMap<>(evidence);
        if (event.user() != null && !ev.containsKey("user")) {
            ev.put("user", event.user());
        }
        ev.put("line", event.raw());
        String target = event.ip() != null ? event.ip() : String.valueOf(event.user());
        return new Finding(event.source(), target, ruleId, Math.min(100, score), description, ev, event.timestamp());
    }

    /** Removes timestamps older than (now - window) from the front of the list, using an Iterator. */
    protected static void evictOlderThan(LinkedList<Instant> times, Instant cutoff) {
        Iterator<Instant> it = times.iterator();
        while (it.hasNext()) {
            if (it.next().isBefore(cutoff)) {
                it.remove();
            } else {
                break;                              // the list is in time order: the rest is newer
            }
        }
    }

    /** No finding: an immutable empty list. */
    protected static List<Finding> none() {
        return List.of();
    }
}
