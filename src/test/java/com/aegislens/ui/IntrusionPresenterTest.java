package com.aegislens.ui;

import com.aegislens.core.Finding;
import com.aegislens.intrusion.LogType;
import com.aegislens.intrusion.MonitorManager.SourceStatus;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Intrusion view logic: type guess, form checks, counters text and the findings filter. */
class IntrusionPresenterTest {

    private static final Instant NOW = Instant.parse("2026-10-30T12:00:00Z");

    @Test
    void guessesTheKindOfLogFromItsName() {
        assertEquals(LogType.SSH, IntrusionPresenter.guessType("auth.log"));
        assertEquals(LogType.WEB, IntrusionPresenter.guessType("Access.LOG"));
        assertEquals(LogType.WINDOWS_XML, IntrusionPresenter.guessType("security.xml"));
        assertEquals(LogType.SYSLOG, IntrusionPresenter.guessType("messages"));
    }

    @Test
    void formProblemsAreExplained() {
        assertTrue(IntrusionPresenter.problem(" ", LogType.SSH, true).isPresent());
        assertTrue(IntrusionPresenter.problem("a.log", null, false).isPresent());
        assertTrue(IntrusionPresenter.problem("a.xml", LogType.WINDOWS_XML, true).orElseThrow().contains("Replay"));
        assertTrue(IntrusionPresenter.problem("a.xml", LogType.WINDOWS_XML, false).isEmpty(), "replay works for every type");
        assertTrue(IntrusionPresenter.problem("auth.log", LogType.SSH, true).isEmpty());
    }

    @Test
    void countersAndTimesReadWell() {
        assertEquals("never", IntrusionPresenter.ago(null, NOW));
        assertEquals("12 s ago", IntrusionPresenter.ago(NOW.minusSeconds(12), NOW));
        assertEquals("3 min ago", IntrusionPresenter.ago(NOW.minusSeconds(200), NOW));
        assertEquals("2 h ago", IntrusionPresenter.ago(NOW.minusSeconds(7300), NOW));
        List<SourceStatus> two = List.of(new SourceStatus("a", "RUNNABLE", 10, 5, 0, 0, 2, NOW),
                new SourceStatus("b", "RUNNABLE", 5, 1, 0, 0, 1, NOW));
        assertEquals("2 sources  ·  15 lines  ·  3 findings", IntrusionPresenter.summary(two));
    }

    @Test
    void filterAndIntrusionCheck() {
        Finding f = new Finding("ssh", "203.0.113.45", "NET-001", 72, "7 failed logins for root");
        assertTrue(IntrusionPresenter.matches(f, "ROOT"));
        assertTrue(IntrusionPresenter.matches(f, "203.0.113"));
        assertFalse(IntrusionPresenter.matches(f, "admin"));
        assertTrue(IntrusionPresenter.isIntrusion(f));
        assertFalse(IntrusionPresenter.isIntrusion(new Finding("file", "a.exe", "MAL-001", 55, "packed")));
    }
}
