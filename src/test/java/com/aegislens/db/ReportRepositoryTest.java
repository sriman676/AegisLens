package com.aegislens.db;

import com.aegislens.core.Finding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** R18 D3-D5, D12: reports give known numbers on known data and use the indexes. */
class ReportRepositoryTest {

    private static final Instant NOW = Instant.parse("2026-10-30T12:00:00Z");
    private static final Instant YESTERDAY = NOW.minusSeconds(86_400);

    private Database db;
    private ReportRepository reports;
    private FindingRepository findings;
    private long attackerFinding;

    @BeforeEach
    void setUp() throws SQLException {
        db = Database.inMemory();
        reports = new ReportRepository(db);
        findings = new FindingRepository(db);
        ScanSessionRepository sessions = new ScanSessionRepository(db);
        long ssh = sessions.begin("INTRUSION", "auth.log");
        long mal = sessions.begin("MALWARE", "downloads");
        attackerFinding = save(ssh, "203.0.113.45", "NET-001", 72, YESTERDAY);
        save(ssh, "203.0.113.45", "NET-001", 80, NOW);
        save(ssh, "203.0.113.45", "NET-003", 40, NOW);
        save(ssh, "198.51.100.7", "NET-001", 70, NOW);
        long dismissed = save(ssh, "198.51.100.7", "NET-001", 70, NOW);
        findings.updateStatus(dismissed, "FALSE_POSITIVE");
        save(mal, "invoice.exe", "MAL-001", 55, NOW);
        new IocRepository(db).addAll("IP", List.of("203.0.113.45"), "test");
        new AiExplanationRepository(db).save(attackerFinding, "offline", "brute force from a documentation IP");
    }

    @AfterEach
    void tearDown() throws SQLException {
        db.close();
    }

    @Test
    void detailViewJoinsRuleModuleExplanationAndIocCheck() throws SQLException {
        List<ReportRepository.DetailRow> rows = reports.findingsWithContext(100);
        assertEquals(5, rows.size(), "the false positive is left out");
        ReportRepository.DetailRow first = rows.stream().filter(r -> r.id() == attackerFinding).findFirst().orElseThrow();
        assertEquals("INTRUSION", first.module());
        assertNotNull(first.ruleName(), "rule name comes from the joined rule table");
        assertEquals("brute force from a documentation IP", first.explanation());
        assertTrue(first.iocHit());
        assertFalse(rows.stream().filter(r -> r.target().equals("invoice.exe")).findFirst().orElseThrow().iocHit());
    }

    @Test
    void perDayAndPerRuleAggregate() throws SQLException {
        List<ReportRepository.DayCount> days = reports.perDay(7, NOW);
        assertEquals(new ReportRepository.DayCount("2026-10-29", "HIGH", 1), days.get(0));
        assertEquals(4, days.stream().filter(d -> d.day().equals("2026-10-30")).mapToInt(ReportRepository.DayCount::count).sum());
        assertTrue(reports.perDay(1, NOW).stream().noneMatch(d -> d.day().equals("2026-10-29")), "window of one day");

        List<ReportRepository.RuleCount> rules = reports.perRule(2);
        assertEquals(1, rules.size(), "HAVING COUNT(*) >= 2 keeps only NET-001");
        assertEquals(new ReportRepository.RuleCount("NET-001", rules.get(0).ruleName(), 3, 80), rules.get(0));

        assertEquals(List.of(new ReportRepository.ModuleCount("INTRUSION", "HIGH", 3),
                new ReportRepository.ModuleCount("INTRUSION", "MEDIUM", 1),
                new ReportRepository.ModuleCount("MALWARE", "MEDIUM", 1)), reports.perModuleAndSeverity());
    }

    @Test
    void attackersAndSubqueries() throws SQLException {
        List<ReportRepository.TargetStats> top = reports.topAttackers(10);
        assertEquals(List.of("203.0.113.45", "198.51.100.7"), top.stream().map(ReportRepository.TargetStats::target).toList());
        assertEquals(3, top.get(0).count());
        assertEquals(YESTERDAY.toString(), top.get(0).firstSeen());

        assertEquals(List.of("203.0.113.45"),
                reports.targetsWithMoreThan(1).stream().map(ReportRepository.TargetStats::target).toList());
        assertEquals(List.of("203.0.113.45"),
                reports.findingsWithIocTarget().stream().map(ReportRepository.TargetStats::target).toList());
    }

    @Test
    void explainShowsTheIndexes() throws SQLException {
        assertTrue(reports.explain(ReportRepository.Query.IOC_TARGETS).contains("idx_ioc_value"),
                reports.explain(ReportRepository.Query.IOC_TARGETS));
        assertTrue(reports.explain(ReportRepository.Query.PER_RULE).contains("idx_finding_rule"),
                reports.explain(ReportRepository.Query.PER_RULE));
        for (ReportRepository.Query q : ReportRepository.Query.values()) {
            assertFalse(reports.explain(q).isBlank(), q.name());
        }
    }

    private long save(long session, String target, String rule, int score, Instant at) throws SQLException {
        Finding f = new Finding("test", target, rule, score, rule + " on " + target, null, at);
        f.setSessionId(session);
        findings.save(f);
        return f.id();
    }
}
