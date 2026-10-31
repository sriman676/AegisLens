package com.aegislens.intrusion;

import com.aegislens.core.Finding;
import com.aegislens.intrusion.LogEvent.Action;

import java.util.List;
import java.util.Map;

/**
 * NET-002: one IP asks for at least N distinct paths that answer 403 or 404 inside the window (default 15 in 60 s):
 * someone is probing for admin pages, backups and config files. Score 55 + 2 per path above N (max 80).
 */
public class PathScanDetector extends LogDetector {

    public static final String RULE = "NET-002";
    static final int BASE_SCORE = 55;
    static final int PER_EXTRA = 2;
    static final int MAX_SCORE = 80;

    private final Thresholds t;
    private final WindowedDistinctCounter<String> paths;

    public PathScanDetector(Thresholds thresholds) {
        super(RULE);
        this.t = thresholds;
        this.paths = new WindowedDistinctCounter<>(thresholds.window(), thresholds.maxTrackedIps());
    }

    @Override
    public List<Finding> detect(LogEvent e) {
        if (e.action() != Action.WEB_REQUEST || e.ip() == null || (e.status() != 403 && e.status() != 404)) {
            return none();
        }
        int n = paths.add(e.ip(), e.path(), e.timestamp());
        if (n < t.pathScanPaths() || !paths.fireOnce(e.ip(), e.timestamp())) {
            return none();
        }
        int score = Math.min(MAX_SCORE, BASE_SCORE + PER_EXTRA * (n - t.pathScanPaths()));
        return List.of(finding(e, score, e.ip() + " requested " + n + " different missing or forbidden paths within "
                + t.window().toSeconds() + " s (scanning)", Map.of("distinctPaths", String.valueOf(n), "lastPath", e.path())));
    }
}
