package com.aegislens.ui;

import org.junit.jupiter.api.Test;

import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.*;

/** G10: untrusted text loses control characters and direction overrides, and is capped. */
class SafeTextTest {

    @Test
    void directionOverridesAreRemovedSoAFileNameCannotHideItsExtension() {
        assertEquals("invoiceexe.pdf", SafeText.shorten("invoice‮exe.pdf"));
        assertEquals("ab", SafeText.shorten("a⁦‏b"));
    }

    @Test
    void controlCharactersBecomeSpacesAndLongTextIsCut() {
        assertEquals("a b c", SafeText.shorten("a\nb\u0007c"));
        String cut = SafeText.shorten("x".repeat(SafeText.MAX_TEXT + 50));
        assertEquals(SafeText.MAX_TEXT + 1, cut.length());
        assertTrue(cut.endsWith("…"));
        assertEquals("", SafeText.shorten(null));
    }

    @Test
    void filePathsShowTheirNameAndTimesAreCompact() {
        assertEquals("tool.elf", SafeText.target("C:\\Users\\x\\tool.elf"));
        assertEquals("auth.log", SafeText.target("/var/log/auth.log"));
        assertEquals("203.0.113.45", SafeText.target("203.0.113.45"));
        assertEquals("http://x.example/a/b", SafeText.target("http://x.example/a/b"), "URLs stay whole");
        assertEquals("10-30 20:37:28", SafeText.time("2026-10-30T15:07:28.123456Z", ZoneId.of("Asia/Kolkata")));
        assertEquals("yesterday", SafeText.time("yesterday"));
    }
}
