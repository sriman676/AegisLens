package com.aegislens.intrusion;

import com.aegislens.core.Finding;
import com.aegislens.intrusion.LogEvent.Action;
import com.aegislens.util.LruMap;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * NET-006: the user agent names an attack tool (sqlmap, nikto, nmap, ...; pattern from the rule table).
 * Score 40, or 55 when the same IP has also received 4xx answers (it is probing, not just visiting).
 * Fires once per IP at 40 and once more if it later qualifies for 55.
 */
public class ScannerAgentDetector extends LogDetector {

    public static final String RULE = "NET-006";
    static final int SCORE = 40;
    static final int SCORE_WITH_4XX = 55;

    private final Pattern agents;
    private final Map<String, Integer> alertedScore;
    private final Map<String, Boolean> saw4xx;

    public ScannerAgentDetector(Thresholds thresholds) {
        super(RULE);
        this.agents = Pattern.compile("(?i)(" + thresholds.scannerAgentPattern() + ")");
        this.alertedScore = new LruMap<>(thresholds.maxTrackedIps());
        this.saw4xx = new LruMap<>(thresholds.maxTrackedIps());
    }

    @Override
    public List<Finding> detect(LogEvent e) {
        if (e.action() != Action.WEB_REQUEST || e.ip() == null) {
            return none();
        }
        if (e.isClientError()) {
            saw4xx.put(e.ip(), Boolean.TRUE);
        }
        if (e.userAgent() == null) {
            return none();
        }
        var m = agents.matcher(e.userAgent());
        if (!m.find()) {
            return none();
        }
        int score = saw4xx.containsKey(e.ip()) ? SCORE_WITH_4XX : SCORE;
        Integer before = alertedScore.get(e.ip());
        if (before != null && before >= score) {
            return none();
        }
        alertedScore.put(e.ip(), score);
        return List.of(finding(e, score, "Attack tool '" + m.group() + "' in the user agent of " + e.ip(),
                Map.of("tool", m.group(), "userAgent", e.userAgent(), "got4xx", String.valueOf(score == SCORE_WITH_4XX))));
    }
}
