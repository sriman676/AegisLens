package com.aegislens.intrusion;

import com.aegislens.core.Finding;
import com.aegislens.intrusion.LogEvent.Action;
import com.aegislens.util.InjectionPatterns;

import java.util.List;
import java.util.Map;

/**
 * WEB-002 in web logs: the request path matches an injection pattern (util.InjectionPatterns: the rule table's SQLi
 * pattern, plus XSS, path traversal and the Log4Shell "${jndi:" lookup, after decoding twice). Score 70.
 */
public class SqlInjectionDetector extends LogDetector {

    public static final String RULE = "WEB-002";
    static final int SCORE = 70;

    private final InjectionPatterns patterns;

    public SqlInjectionDetector(Thresholds thresholds) {
        super(RULE);
        this.patterns = new InjectionPatterns(thresholds.injectionPattern());
    }

    @Override
    public List<Finding> detect(LogEvent e) {
        if (e.action() != Action.WEB_REQUEST || e.path() == null) {
            return none();
        }
        return patterns.find(e.path()).map(hit -> List.of(finding(e, SCORE,
                "Injection attempt (" + hit.kind() + ") from " + e.ip() + " in " + e.path(),
                Map.of("kind", hit.kind(), "match", hit.match(), "path", e.path(), "status", String.valueOf(e.status())))))
                .orElse(none());
    }
}
