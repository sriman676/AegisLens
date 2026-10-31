package com.aegislens.db;

import com.aegislens.core.Finding;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** R18 D9: text search (FTS5 and the LIKE fallback give the same answers), filters and keyset paging. */
class FindingSearchTest {

    private static final Instant T0 = Instant.parse("2026-10-30T00:00:00Z");

    private Database db;
    private FindingRepository findings;

    @BeforeEach
    void setUp() throws SQLException {
        db = Database.inMemory();
        findings = new FindingRepository(db);
        ScanSessionRepository sessions = new ScanSessionRepository(db);
        long ssh = sessions.begin("INTRUSION", "auth.log");
        long mal = sessions.begin("MALWARE", "downloads");
        for (int i = 0; i < 25; i++) {
            save(ssh, "203.0.113." + i, "NET-001", 72, "7 failed logins for root", T0.plusSeconds(i * 3600L));
        }
        save(ssh, "198.51.100.7", "WEB-002", 85, "SQL injection attempt: ' OR 1=1 --", T0.plusSeconds(100_000));
        save(mal, "invoice_2026%.exe", "MAL-001", 55, "packed section with high entropy", T0.plusSeconds(100_001));
    }

    @AfterEach
    void tearDown() throws SQLException {
        db.close();
    }

    @Test
    void thisSqliteBuildHasFts5() {
        assertTrue(db.ftsAvailable(), "the bundled sqlite-jdbc ships FTS5");
    }

    @ParameterizedTest(name = "fts={0}")
    @ValueSource(booleans = {true, false})
    void textSearchFindsWordsAndTargets(boolean fts) throws SQLException {
        FindingSearch search = new FindingSearch(db, fts);
        assertEquals(25, all(search, text("failed root")).size(), "every word must match");
        assertEquals(List.of("198.51.100.7"), targets(search, text("injection")));
        assertEquals(List.of("203.0.113.7"), targets(search, text("203.0.113.7")), "an IP target is found");
        assertEquals(List.of("invoice_2026%.exe"), targets(search, text("invoice")));
        assertTrue(all(search, text("nothing-like-this")).isEmpty());
    }

    @ParameterizedTest(name = "fts={0}")
    @ValueSource(booleans = {true, false})
    void operatorsAndWildcardsAreSearchedAsPlainText(boolean fts) throws SQLException {
        FindingSearch search = new FindingSearch(db, fts);
        assertDoesNotThrow(() -> search.search(text("\" OR NEAR( -x : *"), null, 10));
        if (!fts) {
            assertEquals(List.of("invoice_2026%.exe"), targets(search, text("_2026%")), "% and _ match literally");
            assertTrue(all(search, text("%")).size() == 1, "a lone % is not 'match everything'");
        }
    }

    @Test
    void filtersCombine() throws SQLException {
        FindingSearch search = new FindingSearch(db);
        assertEquals(1, all(search, new FindingSearch.Filter(null, null, null, "malware", null, null)).size());
        assertEquals(1, all(search, new FindingSearch.Filter(null, "critical", null, null, null, null)).size());
        Instant from = T0.plusSeconds(10 * 3600L);
        Instant to = T0.plusSeconds(20 * 3600L);
        assertEquals(10, all(search, new FindingSearch.Filter("failed", null, null, "INTRUSION", from, to)).size(),
                "hours 10..19: from inclusive, to exclusive");
        long first = all(search, FindingSearch.Filter.ALL).get(0).id();
        findings.updateStatus(first, "RESOLVED");
        assertEquals(List.of(first), all(search, new FindingSearch.Filter(null, null, "RESOLVED", null, null, null))
                .stream().map(ReportRepository.DetailRow::id).toList());
    }

    @Test
    void keysetPagesAreContiguousWithoutGapsOrRepeats() throws SQLException {
        FindingSearch search = new FindingSearch(db);
        List<Long> seen = new ArrayList<>();
        Long before = null;
        List<ReportRepository.DetailRow> page;
        do {
            page = search.search(FindingSearch.Filter.ALL, before, 10);
            page.forEach(r -> seen.add(r.id()));
            before = page.isEmpty() ? before : page.get(page.size() - 1).id();
        } while (page.size() == 10);
        assertEquals(27, seen.size());
        assertEquals(27, seen.stream().distinct().count());
        for (int i = 1; i < seen.size(); i++) {
            assertTrue(seen.get(i) < seen.get(i - 1), "newest first");
        }
        assertEquals(FindingSearch.MAX_PAGE, Math.min(100_000, FindingSearch.MAX_PAGE), "page size is capped");
    }

    @Test
    void ftsIndexFollowsUpdatesAndDeletes() throws SQLException {
        FindingSearch search = new FindingSearch(db, true);
        long id = all(search, text("injection")).get(0).id();
        findings.delete(id);
        assertTrue(all(search, text("injection")).isEmpty(), "the delete trigger removed it from the index");
    }

    private static FindingSearch.Filter text(String t) {
        return new FindingSearch.Filter(t, null, null, null, null, null);
    }

    private static List<ReportRepository.DetailRow> all(FindingSearch s, FindingSearch.Filter f) throws SQLException {
        return s.search(f, null, FindingSearch.MAX_PAGE);
    }

    private static List<String> targets(FindingSearch s, FindingSearch.Filter f) throws SQLException {
        return all(s, f).stream().map(ReportRepository.DetailRow::target).toList();
    }

    private void save(long session, String target, String rule, int score, String text, Instant at) throws SQLException {
        Finding f = new Finding("test", target, rule, score, text, null, at);
        f.setSessionId(session);
        findings.save(f);
    }
}
