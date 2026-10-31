package com.aegislens.ui;

import java.util.Locale;
import java.util.Optional;

/**
 * The user's look settings (Settings > Appearance): an accent colour and a base font size, stored in the setting table
 * and applied as one root style on the scene. Only a validated "#RRGGBB" colour and a whole number in range ever reach
 * setStyle, never text from logs or files. The high-contrast design keeps its own colours.
 */
public record Appearance(String accent, int fontSize) {

    public static final String ACCENT_SETTING = "ui.accent";
    public static final String FONT_SETTING = "ui.font.size";
    public static final int MIN_FONT = 11;
    public static final int MAX_FONT = 20;
    public static final int DEFAULT_FONT = 13;
    /** No accent set: each design uses its own. */
    public static final Appearance DEFAULTS = new Appearance(null, DEFAULT_FONT);

    public Appearance {
        accent = colour(accent).orElse(null);
        fontSize = Math.max(MIN_FONT, Math.min(MAX_FONT, fontSize));
    }

    /** From the stored settings; anything broken falls back to the defaults. */
    public static Appearance of(String accentSetting, String fontSetting) {
        int size;
        try {
            size = Integer.parseInt(fontSetting == null ? "" : fontSetting.strip());
        } catch (NumberFormatException e) {
            size = DEFAULT_FONT;
        }
        return new Appearance(accentSetting, size);
    }

    /** "#0e7490" or "0E7490" -> "#0E7490"; anything else is empty. */
    public static Optional<String> colour(String text) {
        if (text == null) {
            return Optional.empty();
        }
        String t = text.strip().toUpperCase(Locale.ROOT);
        t = t.startsWith("#") ? t : "#" + t;
        return t.matches("#[0-9A-F]{6}") ? Optional.of(t) : Optional.empty();
    }

    /** The root style for a design: font size always, accent colour except in high contrast. */
    public String rootStyle(Theme theme) {
        StringBuilder sb = new StringBuilder("-fx-font-size: " + fontSize + "px;");
        if (accent != null && theme != Theme.HIGH_CONTRAST) {
            sb.append(" -al-accent: ").append(accent).append("; -al-primary: ").append(accent)
                    .append("; -fx-accent: ").append(accent).append("; -fx-focus-color: ").append(accent).append(';');
        }
        return sb.toString();
    }
}
