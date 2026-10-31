package com.aegislens.ui;

import com.aegislens.db.FindingSearch;
import com.aegislens.db.ReportRepository;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Logic of the Findings explorer, kept out of JavaFX so it is unit-tested: turns the controls (search text, severity
 * ComboBox, status RadioButtons, module ComboBox) into a search filter, and turns the module x severity counts into the
 * data of the TreeView.
 */
public final class FindingsPresenter {

    /** The "no filter" choice in every ComboBox and the first RadioButton. */
    public static final String ANY = "All";
    public static final List<String> SEVERITIES = List.of(ANY, "CRITICAL", "HIGH", "MEDIUM", "LOW");
    public static final List<String> MODULES = List.of(ANY, "INTRUSION", "HOST", "MALWARE", "WEB", "SANDBOX");
    /** RadioButton label to database status. */
    public static final Map<String, String> STATUSES = Map.of("Open", "OPEN", "Resolved", "RESOLVED",
            "False positive", "FALSE_POSITIVE");
    public static final List<String> STATUS_LABELS = List.of(ANY, "Open", "Resolved", "False positive");

    private FindingsPresenter() {
    }

    /** The search filter for the current control values ("All" and blank text mean no filter). */
    public static FindingSearch.Filter filter(String text, String severity, String statusLabel, String module) {
        return new FindingSearch.Filter(blankToNull(text), anyToNull(severity), STATUSES.get(statusLabel),
                anyToNull(module), null, null);
    }

    /** module -> (severity -> count), both sorted, severities from CRITICAL down. */
    public static Map<String, Map<String, Integer>> tree(List<ReportRepository.ModuleCount> counts) {
        Map<String, Map<String, Integer>> tree = new TreeMap<>();
        for (ReportRepository.ModuleCount c : counts) {
            tree.computeIfAbsent(c.module(), m -> new TreeMap<>((a, b) -> SEVERITIES.indexOf(a) - SEVERITIES.indexOf(b)))
                    .put(c.severity(), c.count());
        }
        return tree;
    }

    /** "INTRUSION (12)" for a tree node. */
    public static String nodeText(String name, int count) {
        return name + " (" + count + ")";
    }

    /** Sum of one module's severities. */
    public static int total(Map<String, Integer> bySeverity) {
        return bySeverity.values().stream().mapToInt(Integer::intValue).sum();
    }

    /** "Showing 200 findings (more available)" for the footer. */
    public static String footer(int shown, boolean more, boolean fullText) {
        return "Showing " + shown + (shown == 1 ? " finding" : " findings") + (more ? " (more available)" : "")
                + "  ·  search: " + (fullText ? "full-text index (FTS5)" : "LIKE");
    }

    private static String anyToNull(String choice) {
        return choice == null || ANY.equals(choice) ? null : choice;
    }

    private static String blankToNull(String text) {
        return text == null || text.isBlank() ? null : text.strip();
    }
}
