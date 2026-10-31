package com.aegislens.ui;

import com.aegislens.db.Database;
import com.aegislens.db.FindingSearch;
import com.aegislens.db.ReportRepository;
import com.aegislens.db.SqlConsole;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** R18 UI logic: control values to filters, tree data, chart series, and example queries that really run. */
class FindingsReportsPresenterTest {

    @Test
    void controlsBecomeAFilter() {
        assertEquals(FindingSearch.Filter.ALL, FindingsPresenter.filter("  ", "All", "All", "All"));
        assertEquals(new FindingSearch.Filter("root", "HIGH", "FALSE_POSITIVE", "MALWARE", null, null),
                FindingsPresenter.filter(" root ", "HIGH", "False positive", "MALWARE"));
    }

    @Test
    void treeIsSortedByModuleThenSeverityFromCriticalDown() {
        Map<String, Map<String, Integer>> tree = FindingsPresenter.tree(List.of(
                new ReportRepository.ModuleCount("MALWARE", "LOW", 1),
                new ReportRepository.ModuleCount("INTRUSION", "MEDIUM", 4),
                new ReportRepository.ModuleCount("INTRUSION", "CRITICAL", 2)));
        assertEquals(List.of("INTRUSION", "MALWARE"), List.copyOf(tree.keySet()));
        assertEquals(List.of("CRITICAL", "MEDIUM"), List.copyOf(tree.get("INTRUSION").keySet()));
        assertEquals(6, FindingsPresenter.total(tree.get("INTRUSION")));
        assertEquals("INTRUSION (6)", FindingsPresenter.nodeText("INTRUSION", 6));
        assertEquals("Showing 1 finding (more available)  ·  search: LIKE", FindingsPresenter.footer(1, true, false));
    }

    @Test
    void seriesHasEveryDayEvenWithoutFindings() {
        Instant now = Instant.parse("2026-10-30T12:00:00Z");
        Map<String, Map<String, Integer>> s = ReportsPresenter.series(List.of(
                new ReportRepository.DayCount("2026-10-29", "HIGH", 3),
                new ReportRepository.DayCount("2026-01-01", "HIGH", 9)), 3, now);
        assertEquals(List.of("2026-10-28", "2026-10-29", "2026-10-30"), List.copyOf(s.get("HIGH").keySet()));
        assertEquals(List.of(0, 3, 0), List.copyOf(s.get("HIGH").values()), "days outside the window are ignored");
        assertEquals(List.of(0, 0, 0), List.copyOf(s.get("LOW").values()));
        assertEquals(List.of("LOW", "MEDIUM", "HIGH", "CRITICAL"), List.copyOf(s.keySet()), "same colour order as the dashboard");
        assertEquals("10-30", ReportsPresenter.shortDay("2026-10-30"));
    }

    @Test
    void everyExampleQueryRunsInTheReadOnlyConsole() throws Exception {
        try (Database db = Database.inMemory()) {
            SqlConsole console = new SqlConsole(db);
            for (Map.Entry<String, String> e : ReportsPresenter.EXAMPLES.entrySet()) {
                assertDoesNotThrow(() -> console.run(e.getValue()), e.getKey());
            }
        }
    }
}
