package com.aegislens.ui;

import java.util.Locale;
import java.util.Optional;

/**
 * Window position, size and maximised flag, saved in the setting table as "x,y,width,height,maximised" (G12) so the
 * window opens where it was closed. Plain Java, so the parsing is unit-tested.
 */
public record WindowState(double x, double y, double width, double height, boolean maximized) {

    /** The setting keys. */
    public static final String SETTING = "ui.window";
    public static final String VIEW_SETTING = "ui.view";
    /** Smallest window we restore (anything smaller is treated as broken). */
    public static final double MIN_WIDTH = 900;
    public static final double MIN_HEIGHT = 600;

    /** Parses a saved value; empty if missing or broken (the caller then uses the default size). */
    public static Optional<WindowState> parse(String text) {
        if (text == null) {
            return Optional.empty();
        }
        String[] p = text.split(",");
        if (p.length != 5) {
            return Optional.empty();
        }
        try {
            WindowState s = new WindowState(Double.parseDouble(p[0]), Double.parseDouble(p[1]), Double.parseDouble(p[2]),
                    Double.parseDouble(p[3]), Boolean.parseBoolean(p[4]));
            return s.width() >= MIN_WIDTH && s.height() >= MIN_HEIGHT && Double.isFinite(s.x()) && Double.isFinite(s.y())
                    ? Optional.of(s) : Optional.empty();
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    @Override
    public String toString() {
        return String.format(Locale.ROOT, "%.0f,%.0f,%.0f,%.0f,%b", x, y, width, height, maximized);
    }
}
