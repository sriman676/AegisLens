package com.aegislens.ui;

import com.aegislens.ai.ExplanationService;
import com.aegislens.ai.LlmBudget;
import com.aegislens.core.Finding;
import com.aegislens.net.ConnectivityMonitor;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class AiPresenterTest {

    @Test
    void choicesBadgesAndLines() {
        assertEquals(List.of("auto", "claude", "local", "offline"), AiPresenter.choices(List.of("claude", "local", "offline")));
        assertEquals("Local model", AiPresenter.label("local"));
        assertEquals("unknown-x", AiPresenter.label("unknown-x"));
        ExplanationService.Explanation e = new ExplanationService.Explanation("claude", "t", false, true, true, null);
        assertEquals(List.of("Claude (cloud)", "cached", "private values hidden"), AiPresenter.badges(e));
        ExplanationService.Explanation fb = new ExplanationService.Explanation("offline", "t", true);
        assertEquals(List.of("Offline templates", "offline fallback"), AiPresenter.badges(fb));
        assertEquals("CRITICAL 90  NET-001  1.2.3.4  ·  x", AiPresenter.findingLine(new Finding("s", "1.2.3.4", "NET-001", 90, "x")));
        assertTrue(AiPresenter.findingLine(new Finding("file", "/home/u/Downloads/tool.elf", "MAL-006", 60, "odd")).contains("  tool.elf  "),
                "file targets show their name, like every other screen");
    }

    @Test
    void budgetAndConnectivity() {
        assertEquals("Cloud AI calls: 3/30 this hour  ·  10/200 today", AiPresenter.budgetText(new LlmBudget.Usage(3, 30, 10, 200)));
        assertEquals("● Offline mode", AiPresenter.connectivityText(Optional.empty()));
        var online = new ConnectivityMonitor.Status(true, Duration.ofMillis(120), Instant.now(), Duration.ZERO, "ok");
        assertEquals("● Online  120 ms", AiPresenter.connectivityText(Optional.of(online)));
        assertEquals("online", AiPresenter.connectivityClass(Optional.of(online)));
        var skewed = new ConnectivityMonitor.Status(true, Duration.ofMillis(5), Instant.now(), Duration.ofMinutes(9), "ok");
        assertTrue(AiPresenter.connectivityText(Optional.of(skewed)).endsWith("clock"));
        var offline = new ConnectivityMonitor.Status(false, Duration.ZERO, Instant.now(), Duration.ZERO, "x");
        assertEquals("offline", AiPresenter.connectivityClass(Optional.of(offline)));
    }
}
