package com.aegislens.intrusion;

import com.aegislens.core.Finding;
import com.aegislens.util.CidrSet;
import com.aegislens.util.LruMap;

import java.util.List;
import java.util.Map;

/**
 * NET-005: the event's IP is on a threat-intelligence list (loaded from the ioc table into CidrSets by the app).
 * Score 75, or 90 if it is on a botnet command-and-control list. Fires once per IP. The sets can be swapped
 * after a feed update without stopping the detector (volatile).
 */
public class ThreatIntelDetector extends LogDetector {

    public static final String RULE = "NET-005";
    static final int SCORE = 75;
    static final int SCORE_C2 = 90;

    private volatile CidrSet blocklist;
    private volatile CidrSet commandAndControl;
    private final Map<String, Boolean> alerted;

    public ThreatIntelDetector(CidrSet blocklist, CidrSet commandAndControl, Thresholds thresholds) {
        super(RULE);
        this.blocklist = blocklist;
        this.commandAndControl = commandAndControl;
        this.alerted = new LruMap<>(thresholds.maxTrackedIps());
    }

    /** Replaces both lists (after a feed refresh). */
    public void update(CidrSet blocklist, CidrSet commandAndControl) {
        this.blocklist = blocklist;
        this.commandAndControl = commandAndControl;
    }

    @Override
    public List<Finding> detect(LogEvent e) {
        if (e.ip() == null || alerted.containsKey(e.ip())) {
            return none();
        }
        boolean c2 = commandAndControl.contains(e.ip());
        if (!c2 && !blocklist.contains(e.ip())) {
            return none();
        }
        alerted.put(e.ip(), Boolean.TRUE);
        String list = c2 ? "a botnet command-and-control list" : "a threat-intelligence blocklist";
        return List.of(finding(e, c2 ? SCORE_C2 : SCORE, e.ip() + " is on " + list, Map.of("list", c2 ? "c2" : "blocklist")));
    }
}
