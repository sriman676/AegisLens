package com.aegislens.ui;

import com.aegislens.core.Finding;
import com.aegislens.util.Ranking;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Logic of the Web view, kept out of JavaFX so it is unit-tested: a one-line verdict, readable reasons from a finding's
 * evidence, and the addresses in a text file of URLs.
 */
public final class WebPresenter {

    /** Most addresses checked from one file. */
    public static final int MAX_BATCH = 1000;

    private WebPresenter() {
    }

    /** "No warning signs found" or the worst finding, e.g. "Suspicious: HIGH (score 75)". */
    public static String verdict(List<Finding> findings) {
        List<Finding> worst = Ranking.topN(findings, 1);          // Finding sorts the worst first
        return worst.isEmpty() ? "No warning signs found"
                : "Suspicious: " + worst.get(0).severity() + " (score " + worst.get(0).score() + ")";
    }

    /** One line per reason: the finding's rule and score, then its evidence without the "note-" prefix. */
    public static List<String> reasons(Finding f) {
        List<String> lines = new ArrayList<>();
        lines.add(f.ruleId() + "  " + f.score() + "  " + f.description());
        for (Map.Entry<String, String> e : f.evidence().entrySet()) {
            String key = e.getKey().startsWith("note-") ? "note" : e.getKey();
            lines.add("    " + key + ": " + e.getValue());
        }
        return lines;
    }

    /** The addresses in a text file: one per line, blank lines and # comments skipped, at most MAX_BATCH. */
    public static List<String> addresses(List<String> lines) {
        return lines.stream().map(String::strip).filter(l -> !l.isEmpty() && !l.startsWith("#")).limit(MAX_BATCH).toList();
    }
}
