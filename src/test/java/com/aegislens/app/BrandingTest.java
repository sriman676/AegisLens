package com.aegislens.app;

import com.aegislens.db.Database;
import com.aegislens.response.HtmlReportExporter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Customisation: organisation name and logo are checked, stored, and shown safely on the report. */
class BrandingTest {

    private static final byte[] PNG = {(byte) 0x89, 'P', 'N', 'G', 13, 10, 26, 10, 0, 0, 0, 13};

    @TempDir
    Path dir;

    @Test
    void onlyRealPngOrJpegLogosAreStored() throws Exception {
        Path data = Files.createDirectories(dir.resolve("data"));
        Path fake = Files.writeString(dir.resolve("logo.png"), "<svg onload=alert(1)>");
        assertTrue(Branding.storeLogo(data, fake).isPresent(), "an SVG renamed to .png is refused by its bytes");
        Path big = Files.write(dir.resolve("big.png"), new byte[Branding.MAX_LOGO_BYTES + 1]);
        assertTrue(Branding.storeLogo(data, big).isPresent());
        assertTrue(Branding.storeLogo(data, Files.write(dir.resolve("ok.png"), PNG)).isEmpty());
        assertTrue(Files.exists(data.resolve(Branding.LOGO_FILE)));
        Branding.removeLogo(data);
        assertFalse(Files.exists(data.resolve(Branding.LOGO_FILE)));
        assertEquals("ACME SOC", Branding.cleanName("  ACME\nSOC "));
        assertEquals(Branding.MAX_NAME, Branding.cleanName("x".repeat(200)).length());
    }

    @Test
    void theReportShowsTheEscapedNameAndTheEmbeddedLogo() throws Exception {
        AppConfig cfg = AppConfig.load(null, Map.of(), new String[] {"--data.dir=" + dir.resolve("data"), "--feeds.enabled=false"});
        try (Database db = Database.inMemory()) {
            ScanCoordinator c = new ScanCoordinator(db, cfg);
            c.start();
            try {
                Files.createDirectories(cfg.paths().dataDir());
                Branding.storeLogo(cfg.paths().dataDir(), Files.write(dir.resolve("ok.png"), PNG));
                c.saveSetting(Branding.NAME_SETTING, "Lab <b>7</b>");
                Path html = dir.resolve("r.html");
                new HtmlReportExporter(db).export(html, Instant.now(), Branding.load(c));
                String text = Files.readString(html);
                assertTrue(text.contains("<h1>Lab &lt;b&gt;7&lt;/b&gt; · AegisLens report</h1>"), "name escaped");
                assertTrue(text.contains("src=\"data:image/png;base64,"), "logo embedded, nothing loaded from outside");
                assertTrue(text.contains("img-src data:"));
            } finally {
                c.shutdown();
            }
        }
    }
}
