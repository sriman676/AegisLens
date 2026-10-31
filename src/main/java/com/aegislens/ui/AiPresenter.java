package com.aegislens.ui;

import com.aegislens.ai.ExplanationService;
import com.aegislens.ai.LlmBudget;
import com.aegislens.core.Finding;
import com.aegislens.net.ConnectivityMonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Text for the AI view and the sidebar's connectivity chip: provider labels for the ComboBox, the badges under an
 * answer, the budget counter, and Online / Offline. Plain Java, so it is unit-tested without JavaFX.
 */
public final class AiPresenter {

    private static final Map<String, String> LABELS = Map.of(
            ExplanationService.AUTO, "Auto (best available)",
            "claude", "Claude (cloud)",
            "gemini", "Gemini (cloud)",
            "local", "Local model",
            "splitshield", "SplitShield-XAI context",
            "offline", "Offline templates",
            "offline+splitshield", "Offline templates + SplitShield");

    private AiPresenter() {
    }

    /** "auto" first, then the registered providers in fallback order. */
    public static List<String> choices(List<String> providerNames) {
        List<String> all = new ArrayList<>();
        all.add(ExplanationService.AUTO);
        all.addAll(providerNames);
        return all;
    }

    public static String label(String provider) {
        return LABELS.getOrDefault(provider, provider);
    }

    /** "CRITICAL 90  NET-001  203.0.113.45 · login after brute force" for the findings list. */
    public static String findingLine(Finding f) {
        return f.severity() + " " + f.score() + "  " + f.ruleId() + "  " + SafeText.target(f.target()) + "  ·  " + f.description();
    }

    /** Small labels under the answer: who answered, cached, fell back, private values hidden. */
    public static List<String> badges(ExplanationService.Explanation e) {
        List<String> b = new ArrayList<>();
        b.add(label(e.provider()));
        if (e.cached()) {
            b.add("cached");
        }
        if (e.fellBack()) {
            b.add("offline fallback");
        }
        if (e.redacted()) {
            b.add("private values hidden");
        }
        return b;
    }

    public static String budgetText(LlmBudget.Usage u) {
        String hour = u.perHour() == Integer.MAX_VALUE ? "no limit" : u.lastHour() + "/" + u.perHour();
        String day = u.perDay() == Integer.MAX_VALUE ? "no limit" : u.lastDay() + "/" + u.perDay();
        return "Cloud AI calls: " + hour + " this hour  ·  " + day + " today";
    }

    /** The sidebar chip text; empty status means no cloud AI is configured. */
    public static String connectivityText(Optional<ConnectivityMonitor.Status> status) {
        if (status.isEmpty()) {
            return "● Offline mode";
        }
        ConnectivityMonitor.Status s = status.get();
        if (s.checkedAt().getEpochSecond() == 0) {
            return "● Checking…";
        }
        String text = s.online() ? "● Online  " + s.latency().toMillis() + " ms" : "● Offline";
        return s.clockWarning() ? text + "  ⚠ clock" : text;
    }

    /** "online", "offline" or "checking", used as a style class. */
    public static String connectivityClass(Optional<ConnectivityMonitor.Status> status) {
        if (status.isEmpty()) {
            return "offline";
        }
        return status.get().checkedAt().getEpochSecond() == 0 ? "checking" : status.get().online() ? "online" : "offline";
    }
}
