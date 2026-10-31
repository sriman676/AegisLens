package com.aegislens.intrusion;

import com.aegislens.core.Finding;
import com.aegislens.intrusion.LogEvent.Action;

import java.util.List;
import java.util.Map;

/**
 * NET-007: one IP tries at least N different user names inside the window (default 5 in 60 s): password spraying.
 * Score 65 + 3 per user name above N (max 85).
 */
public class PasswordSprayDetector extends LogDetector {

    public static final String RULE = "NET-007";
    static final int BASE_SCORE = 65;
    static final int PER_EXTRA = 3;
    static final int MAX_SCORE = 85;

    private final Thresholds t;
    private final WindowedDistinctCounter<String> users;

    public PasswordSprayDetector(Thresholds thresholds) {
        super(RULE);
        this.t = thresholds;
        this.users = new WindowedDistinctCounter<>(thresholds.window(), thresholds.maxTrackedIps());
    }

    @Override
    public List<Finding> detect(LogEvent e) {
        boolean attempt = e.action() == Action.FAILED_LOGIN || e.action() == Action.INVALID_USER;
        if (!attempt || e.ip() == null || e.user() == null) {
            return none();
        }
        int n = users.add(e.ip(), e.user(), e.timestamp());
        if (n < t.sprayUsers() || !users.fireOnce(e.ip(), e.timestamp())) {
            return none();
        }
        int score = Math.min(MAX_SCORE, BASE_SCORE + PER_EXTRA * (n - t.sprayUsers()));
        return List.of(finding(e, score, e.ip() + " tried " + n + " different user names within "
                + t.window().toSeconds() + " s (password spraying)", Map.of("distinctUsers", String.valueOf(n))));
    }
}
