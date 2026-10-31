package com.aegislens.ai;

import com.aegislens.core.Finding;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

/**
 * Explains findings from text templates in src/main/resources/templates/ (one file per rule id, plus default.txt).
 * Needs no network and no key, so the demo can never fail because of Wi-Fi.
 * Placeholders: {rule} {severity} {score} {target} {description} {evidence}
 */
public class OfflineProvider implements LlmProvider {

    @Override
    public String name() {
        return "offline";
    }

    @Override
    public String explain(Finding f) {
        String template = load(f.ruleId());
        String evidence = f.evidence().entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining(", "));
        return template
                .replace("{rule}", f.ruleId())
                .replace("{severity}", f.severity().name())
                .replace("{score}", Integer.toString(f.score()))
                .replace("{target}", f.target())
                .replace("{description}", f.description())
                .replace("{evidence}", evidence.isEmpty() ? "none" : evidence);
    }

    private String load(String ruleId) {
        // Only letters, digits and '-' are allowed in a template name (no path tricks).
        String safe = ruleId.matches("[A-Za-z0-9-]+") ? ruleId : "default";
        String text = read("/templates/" + safe + ".txt");
        return text != null ? text : read("/templates/default.txt");
    }

    private String read(String resource) {
        try (InputStream in = OfflineProvider.class.getResourceAsStream(resource)) {
            return in == null ? null : new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }
}
