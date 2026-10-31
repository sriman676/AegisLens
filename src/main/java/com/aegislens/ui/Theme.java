package com.aegislens.ui;

/**
 * The two looks of AegisLens, each with its own stylesheet and its own design (not just swapped colours):
 * DARK is a slate security-operations console with glowing glass cards, LIGHT is a clean report-style layout with
 * flat white cards and coloured top edges. HIGH_CONTRAST is the dark design with black panels, white text and thick
 * yellow focus rings for low vision (G11).
 */
public enum Theme {
    DARK("Dark", "/ui/aegislens-dark.css"),
    LIGHT("Light", "/ui/aegislens-light.css"),
    HIGH_CONTRAST("High contrast", "/ui/aegislens-contrast.css");

    /** The setting key that remembers the choice. */
    public static final String SETTING = "ui.theme";

    private final String label;
    private final String stylesheet;

    Theme(String label, String stylesheet) {
        this.label = label;
        this.stylesheet = stylesheet;
    }

    public String label() {
        return label;
    }

    public String stylesheet() {
        return stylesheet;
    }

    /** The stored name, or DARK for anything unknown. */
    public static Theme fromSetting(String value) {
        for (Theme t : values()) {
            if (t.name().equalsIgnoreCase(value)) {
                return t;
            }
        }
        return DARK;
    }
}
