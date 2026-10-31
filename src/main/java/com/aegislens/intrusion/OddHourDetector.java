package com.aegislens.intrusion;

import com.aegislens.core.Finding;
import com.aegislens.intrusion.LogEvent.Action;

import java.time.LocalTime;
import java.util.List;
import java.util.Map;

/**
 * NET-003: a successful login during quiet hours (default 00:00 to 05:00 in the server's zone). Score 35.
 * Quiet hours may wrap past midnight (for example 22:00 to 06:00).
 */
public class OddHourDetector extends LogDetector {

    public static final String RULE = "NET-003";
    static final int SCORE = 35;

    private final Thresholds t;

    public OddHourDetector(Thresholds thresholds) {
        super(RULE);
        this.t = thresholds;
    }

    @Override
    public List<Finding> detect(LogEvent e) {
        if (e.action() != Action.SUCCESS_LOGIN) {
            return none();
        }
        LocalTime local = e.timestamp().atZone(t.zone()).toLocalTime();
        if (!isQuiet(local)) {
            return none();
        }
        return List.of(finding(e, SCORE, "Login by " + e.user() + " from " + e.ip() + " at " + local.withNano(0)
                + ", inside quiet hours " + t.quietStart() + "-" + t.quietEnd(), Map.of("localTime", local.withNano(0).toString())));
    }

    boolean isQuiet(LocalTime time) {
        LocalTime start = t.quietStart();
        LocalTime end = t.quietEnd();
        if (start.isBefore(end)) {
            return !time.isBefore(start) && time.isBefore(end);
        }
        return !time.isBefore(start) || time.isBefore(end);          // wraps past midnight
    }
}
