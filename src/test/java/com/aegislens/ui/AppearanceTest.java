package com.aegislens.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Customisation: only a validated colour and an in-range size ever reach the scene's style. */
class AppearanceTest {

    @Test
    void coloursAreValidatedAndNormalised() {
        assertEquals("#0E7490", Appearance.colour("0e7490").orElseThrow());
        assertEquals("#22D3EE", Appearance.colour(" #22d3ee ").orElseThrow());
        assertTrue(Appearance.colour("red").isEmpty());
        assertTrue(Appearance.colour("#12345").isEmpty());
        assertTrue(Appearance.colour("#123456; -fx-background-image: url(x)").isEmpty(), "no style injection");
    }

    @Test
    void brokenSettingsFallBackAndSizesAreClamped() {
        assertEquals(Appearance.DEFAULTS, Appearance.of(null, null));
        assertEquals(Appearance.MAX_FONT, Appearance.of(null, "99").fontSize());
        assertEquals(Appearance.MIN_FONT, Appearance.of(null, "2").fontSize());
        assertEquals(Appearance.DEFAULT_FONT, Appearance.of("nonsense", "big").fontSize());
        assertNull(Appearance.of("nonsense", "14").accent());
    }

    @Test
    void highContrastKeepsItsColours() {
        Appearance a = Appearance.of("#FF00AA", "16");
        assertTrue(a.rootStyle(Theme.DARK).contains("-al-primary: #FF00AA;"));
        assertTrue(a.rootStyle(Theme.LIGHT).startsWith("-fx-font-size: 16px;"));
        assertEquals("-fx-font-size: 16px;", a.rootStyle(Theme.HIGH_CONTRAST));
    }
}
