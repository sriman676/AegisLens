package com.aegislens.app;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Your organisation's name and logo (Settings > Appearance), shown in the About box and on the HTML report. The logo is
 * copied into the data folder after a check: a PNG or JPEG by its first bytes and at most 512 KB, so the report never
 * embeds anything else. The name is plain text (escaped wherever it is shown).
 */
public record Branding(String name, byte[] logo) {

    public static final String NAME_SETTING = "brand.name";
    public static final String LOGO_FILE = "branding-logo";
    public static final int MAX_LOGO_BYTES = 512 * 1024;
    public static final int MAX_NAME = 80;

    /** The saved branding (empty name and no logo when nothing is set). */
    public static Branding load(ScanCoordinator coordinator) {
        Path logo = coordinator.config().paths().dataDir().resolve(LOGO_FILE);
        byte[] bytes = null;
        try {
            if (Files.isRegularFile(logo) && Files.size(logo) <= MAX_LOGO_BYTES) {
                bytes = Files.readAllBytes(logo);
            }
        } catch (IOException e) {
            bytes = null;                            // a missing or unreadable logo is simply not shown
        }
        return new Branding(coordinator.setting(NAME_SETTING, ""), bytes != null && imageType(bytes).isPresent() ? bytes : null);
    }

    /** Checks and copies a logo into the data folder. Returns why it was refused, or empty when stored. */
    public static Optional<String> storeLogo(Path dataDir, Path source) throws IOException {
        if (Files.size(source) > MAX_LOGO_BYTES) {
            return Optional.of("The logo is larger than " + MAX_LOGO_BYTES / 1024 + " KB.");
        }
        byte[] bytes = Files.readAllBytes(source);
        if (imageType(bytes).isEmpty()) {
            return Optional.of("Only PNG or JPEG images can be used as a logo.");
        }
        Files.write(dataDir.resolve(LOGO_FILE), bytes);
        return Optional.empty();
    }

    /** Removes the stored logo (no error if there is none). */
    public static void removeLogo(Path dataDir) throws IOException {
        Files.deleteIfExists(dataDir.resolve(LOGO_FILE));
    }

    /** A clean, single-line name of at most 80 characters. */
    public static String cleanName(String text) {
        String t = text == null ? "" : text.replaceAll("\\p{Cntrl}", " ").strip();
        return t.length() <= MAX_NAME ? t : t.substring(0, MAX_NAME);
    }

    /** "image/png" or "image/jpeg" judged by the first bytes (magic numbers), never by the file name. */
    public static Optional<String> imageType(byte[] b) {
        if (b.length > 8 && (b[0] & 0xFF) == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G') {
            return Optional.of("image/png");
        }
        if (b.length > 3 && (b[0] & 0xFF) == 0xFF && (b[1] & 0xFF) == 0xD8 && (b[2] & 0xFF) == 0xFF) {
            return Optional.of("image/jpeg");
        }
        return Optional.empty();
    }
}
