package com.aegislens.intrusion;

import com.aegislens.core.Finding;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * Runs every host detector over Sysmon events and keeps only findings of rules that are switched on (Settings >
 * Detection rules). The detectors keep no state, so one engine can replay any number of exports.
 */
public class HostDetectionEngine {

    private final List<HostDetector> detectors;
    private final Predicate<String> enabled;

    /**
     * @param network the network detector (it needs the threat lists, so the app builds it)
     * @param enabled true when a rule id is switched on
     */
    public HostDetectionEngine(HostNetworkDetector network, Predicate<String> enabled) {
        this.detectors = List.of(new ProcessStartDetector(), new ParentChildDetector(), network, new PersistenceDetector());
        this.enabled = enabled;
    }

    /** Every finding for one event, from every detector. */
    public List<Finding> process(SysmonEvent event) {
        List<Finding> found = new ArrayList<>();
        for (HostDetector d : detectors) {
            for (Finding f : d.detect(event)) {
                if (enabled.test(f.ruleId())) {
                    found.add(f);
                }
            }
        }
        return found;
    }
}
