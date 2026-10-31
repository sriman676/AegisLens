package com.aegislens.ui;

import com.aegislens.app.AllowList;
import com.aegislens.app.AppConfig;
import com.aegislens.intel.FeedUpdater;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Threat Intel and Settings logic: feed states, the VirusTotal line, form checks and the read-only options. */
class SystemPresenterTest {

    private static final Instant NOW = Instant.parse("2026-10-30T12:00:00Z");

    @Test
    void feedStates() {
        assertEquals("OFF", SystemPresenter.feedState(status(false, null, false, NOW)));
        assertEquals("ERROR", SystemPresenter.feedState(status(true, "HTTP 503", false, NOW)));
        assertEquals("STALE", SystemPresenter.feedState(status(true, null, true, NOW)));
        assertEquals("STALE", SystemPresenter.feedState(status(true, null, false, null)), "never downloaded");
        assertEquals("OK", SystemPresenter.feedState(status(true, null, false, NOW)));
        assertEquals("never", SystemPresenter.feedAge(status(true, null, false, null), NOW));
    }

    @Test
    void virusTotalLineNeverContainsTheKey() {
        assertTrue(SystemPresenter.virusTotalText(true, 2).contains("hidden"));
        assertTrue(SystemPresenter.virusTotalText(false, 0).contains("VT_API_KEY"));
    }

    @Test
    void allowListIsCleanedAndBadEntriesAreNamed() {
        String text = SystemPresenter.normalizeAllowList("10.0.0.0/8\n user:backup ,10.0.0.0/8\r\n\n2001:db8::1");
        assertEquals("10.0.0.0/8, user:backup, 2001:db8::1", text);
        assertEquals(List.of(), AllowList.invalidEntries(text));
        assertEquals(List.of("not-an-ip", "user:"), AllowList.invalidEntries("10.0.0.1, not-an-ip, user:, user:a, user:a"));
    }

    @Test
    void numbersAndProxyAreChecked() {
        assertEquals(90, SystemPresenter.days(" 90 ").orElseThrow());
        assertTrue(SystemPresenter.days("0").isEmpty());
        assertTrue(SystemPresenter.days("99999").isEmpty());
        assertTrue(SystemPresenter.days("ninety").isEmpty());
        assertEquals(5.0, SystemPresenter.threshold("5").orElseThrow());
        assertTrue(SystemPresenter.threshold("-1").isEmpty());
        assertTrue(SystemPresenter.threshold("NaN").isEmpty());
        assertTrue(SystemPresenter.proxyProblem("", "").isEmpty(), "blank host = no fixed proxy");
        assertTrue(SystemPresenter.proxyProblem("proxy.example.org", "3128").isEmpty());
        assertTrue(SystemPresenter.proxyProblem("proxy.example.org", "70000").isPresent());
        assertTrue(SystemPresenter.proxyProblem("evil host;rm", "80").isPresent());
    }

    @Test
    void startupOptionsShowDefaultsAndValues() throws Exception {
        AppConfig cfg = AppConfig.load(null, Map.of(), new String[] {"--oddhour.zone=UTC"});
        List<SystemPresenter.Option> options = SystemPresenter.startupOptions(cfg, Map.of("oddhour.zone", "Asia/Kolkata"));
        assertEquals(SystemPresenter.STARTUP_KEYS.size(), options.size());
        assertTrue(options.contains(new SystemPresenter.Option("oddhour.zone", "Asia/Kolkata", "UTC")),
                "the command line wins over the file, and both are shown");
        assertTrue(options.contains(new SystemPresenter.Option("syslog.bind", "", "(default)")));
        assertEquals("Indicators stored: CIDR 1756  ·  IP 1", SystemPresenter.iocLine(Map.of("IP", 1, "CIDR", 1756)));
    }

    private static FeedUpdater.Status status(boolean enabled, String error, boolean stale, Instant last) {
        return new FeedUpdater.Status("f", enabled, 10, last, stale, error, "test");
    }
}
