package com.aegislens.intrusion;

import com.aegislens.core.Finding;
import com.aegislens.util.CidrSet;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * R13 labelled evaluation: every line of sample-data/labelled-events.csv goes through the real parsers and detectors.
 * An alert counts as correct when its (rule, address) pair is labelled attack for that rule; an alert on any other pair
 * is a false positive; a labelled pair without an alert is missed. The per-rule table is printed and written to
 * target/evaluation.md for the report. The asserts only guard against regressions; the honest numbers are in the table.
 */
class EvaluationTest {

    private static final Pattern IP = Pattern.compile("from (\\S+) port|^(\\S+) - -");

    @Test
    void precisionAndRecallPerRule() throws Exception {
        List<String[]> rows = csv(Files.readString(Path.of("sample-data", "labelled-events.csv")));
        Clock clock = Clock.fixed(Instant.parse("2026-10-31T00:00:00Z"), ZoneOffset.UTC);
        DetectionEngine engine = new DetectionEngine(Thresholds.defaults(ZoneOffset.UTC), new CidrSet(), new CidrSet());
        LogSource ssh = new SshLogSource(clock, ZoneOffset.UTC);
        LogSource web = new WebLogSource();
        Set<String> expected = new TreeSet<>();
        Set<String> alerts = new TreeSet<>();
        for (String[] r : rows.subList(1, rows.size())) {
            String ip = address(r[1]);
            if (r[2].equals("attack")) {
                expected.add(r[3] + " " + ip);
            }
            Optional<LogEvent> event = (r[0].equals("ssh") ? ssh : web).parse(r[1]);
            if (event.isPresent()) {
                for (Finding f : engine.process(event.get())) {
                    alerts.add(f.ruleId() + " " + f.target());
                }
            }
        }
        Map<String, int[]> perRule = new TreeMap<>();                  // rule -> {tp, fp, fn}
        for (String a : alerts) {
            perRule.computeIfAbsent(rule(a), k -> new int[3])[expected.contains(a) ? 0 : 1]++;
        }
        for (String e : expected) {
            if (!alerts.contains(e)) {
                perRule.computeIfAbsent(rule(e), k -> new int[3])[2]++;
            }
        }
        StringBuilder table = new StringBuilder("| Rule | Correct alerts | False alerts | Missed | Precision | Recall |\n|---|---|---|---|---|---|\n");
        int tp = 0, fp = 0, fn = 0;
        for (Map.Entry<String, int[]> e : perRule.entrySet()) {
            int[] c = e.getValue();
            tp += c[0];
            fp += c[1];
            fn += c[2];
            table.append(String.format("| %s | %d | %d | %d | %s | %s |%n", e.getKey(), c[0], c[1], c[2], ratio(c[0], c[0] + c[1]), ratio(c[0], c[0] + c[2])));
        }
        table.append(String.format("| **all** | %d | %d | %d | %s | %s |%n", tp, fp, fn, ratio(tp, tp + fp), ratio(tp, tp + fn)));
        Set<String> falseAlerts = new HashSet<>(alerts);
        falseAlerts.removeAll(expected);
        table.append("\nFalse alerts: ").append(falseAlerts.isEmpty() ? "none" : new TreeSet<>(falseAlerts)).append('\n');
        Files.createDirectories(Path.of("target"));
        Files.writeString(Path.of("target", "evaluation.md"), table);
        System.out.println(table);

        assertTrue(tp >= 0.9 * (tp + fn), "recall fell below 90 %:\n" + table);
        assertTrue(fp <= 1, "more false alerts than the known one (a sprayer also counts as brute force):\n" + table);
    }

    private static String rule(String pair) {
        return pair.substring(0, pair.indexOf(' '));
    }

    private static String address(String line) {
        Matcher m = IP.matcher(line);
        return m.find() ? (m.group(1) != null ? m.group(1) : m.group(2)) : "?";
    }

    private static String ratio(int a, int b) {
        return b == 0 ? "-" : String.format("%.2f", (double) a / b);
    }

    @Test
    void csvReaderAcceptsWindowsLineEndings() {
        assertArrayEquals(new String[] {"ssh", "x", "attack", "NET-001"}, csv("source,line,label,expected_rule\r\nssh,x,attack,NET-001\r\n").get(1),
                "Git on Windows checks the CSV out with CRLF; no cell may keep a stray \\r");
    }

    /** A small RFC 4180 reader (quoted cells with "" for a quote); enough for this file. LF or CRLF line endings. */
    static List<String[]> csv(String text) {
        List<String[]> rows = new ArrayList<>();
        for (String line : text.split("\r?\n")) {
            if (line.isBlank()) {
                continue;
            }
            List<String> cells = new ArrayList<>();
            StringBuilder cell = new StringBuilder();
            boolean quoted = false;
            for (int i = 0; i < line.length(); i++) {
                char c = line.charAt(i);
                if (quoted && c == '"' && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    cell.append('"');
                    i++;
                } else if (c == '"') {
                    quoted = !quoted;
                } else if (c == ',' && !quoted) {
                    cells.add(cell.toString());
                    cell.setLength(0);
                } else {
                    cell.append(c);
                }
            }
            cells.add(cell.toString());
            rows.add(cells.toArray(new String[0]));
        }
        return rows;
    }
}
