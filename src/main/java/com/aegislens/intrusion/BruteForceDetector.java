package com.aegislens.intrusion;

import com.aegislens.core.Finding;
import com.aegislens.intrusion.LogEvent.Action;
import com.aegislens.util.LruMap;

import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * NET-001: at least N failed logins from one IP inside the window (default 5 in 60 s). Fires once per burst with
 * score 60 + 5 per failure above N (max 85). If that IP then logs in successfully within 5 minutes, it escalates
 * once to CRITICAL (90): the attacker probably guessed the password. Per-IP state lives in an LruMap (bounded).
 */
public class BruteForceDetector extends LogDetector {

    public static final String RULE = "NET-001";
    static final int BASE_SCORE = 60;
    static final int PER_EXTRA = 5;
    static final int MAX_SCORE = 85;
    static final int ESCALATED_SCORE = 90;

    /** Failures of one IP inside the window, and the state of its current alert. */
    private static final class IpState {
        final LinkedList<Instant> failures = new LinkedList<>();
        Instant alertedAt;
        Instant lastFailure;
        int failuresAtAlert;
        boolean escalated;
    }

    private final Thresholds t;
    private final Map<String, IpState> byIp;

    public BruteForceDetector(Thresholds thresholds) {
        super(RULE);
        this.t = thresholds;
        this.byIp = new LruMap<>(thresholds.maxTrackedIps());
    }

    @Override
    public List<Finding> detect(LogEvent e) {
        if (e.ip() == null) {
            return none();
        }
        if (e.action() == Action.FAILED_LOGIN) {
            return onFailure(e);
        }
        if (e.action() == Action.SUCCESS_LOGIN) {
            return onSuccess(e);
        }
        return none();
    }

    private List<Finding> onFailure(LogEvent e) {
        IpState s = byIp.computeIfAbsent(e.ip(), ip -> new IpState());
        evictOlderThan(s.failures, e.timestamp().minus(t.window()));
        s.failures.addLast(e.timestamp());
        s.lastFailure = e.timestamp();
        int n = s.failures.size();
        boolean newBurst = s.alertedAt == null || s.alertedAt.isBefore(e.timestamp().minus(t.window()));
        if (n >= t.bruteForceFailures() && newBurst) {
            s.alertedAt = e.timestamp();
            s.escalated = false;
            s.failuresAtAlert = n;
            int score = Math.min(MAX_SCORE, BASE_SCORE + PER_EXTRA * (n - t.bruteForceFailures()));
            return List.of(finding(e, score, n + " failed logins from " + e.ip() + " within " + t.window().toSeconds() + " s",
                    evidence(n)));
        }
        if (s.alertedAt != null && !newBurst) {
            s.failuresAtAlert = n;                    // keep counting this burst for a later escalation
        }
        return none();
    }

    private List<Finding> onSuccess(LogEvent e) {
        IpState s = byIp.get(e.ip());
        if (s == null || s.alertedAt == null || s.escalated
                || s.lastFailure.isBefore(e.timestamp().minus(t.escalation()))) {
            return none();
        }
        s.escalated = true;
        Map<String, String> ev = evidence(s.failuresAtAlert);
        ev.put("escalation", "successful login after the failures");
        return List.of(finding(e, ESCALATED_SCORE, "Login succeeded for " + e.user() + " from " + e.ip()
                + " right after " + s.failuresAtAlert + " failed logins: the password was probably guessed", ev));
    }

    private Map<String, String> evidence(int failures) {
        Map<String, String> ev = new HashMap<>();
        ev.put("failures", String.valueOf(failures));
        ev.put("window", t.window().toSeconds() + "s");
        return ev;
    }

    int trackedIps() {
        return byIp.size();
    }
}
