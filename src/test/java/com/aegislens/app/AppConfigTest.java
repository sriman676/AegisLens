package com.aegislens.app;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AppConfigTest {

    @TempDir
    Path dir;

    @Test
    void laterSourcesWin() throws Exception {
        Path file = dir.resolve(AppPaths.CONFIG_FILE);
        Files.writeString(file, "dedupe.cooldown.minutes=5\nbus.capacity=50\nscan.threads=3\n");
        Map<String, String> env = Map.of("AEGISLENS_BUS_CAPACITY", "60", "AEGISLENS_SCAN_THREADS", "4", "PATH", "x");
        AppConfig config = AppConfig.load(file, env, new String[] {"--scan.threads=8", "not-an-option", "--bad"});
        assertEquals(Duration.ofMinutes(5), config.getMinutes(AppConfig.DEDUPE_COOLDOWN_MINUTES, 10), "file only");
        assertEquals(60, config.getInt(AppConfig.BUS_CAPACITY, 1), "environment beats file");
        assertEquals(8, config.getInt(AppConfig.SCAN_THREADS, 1), "command line beats environment");
    }

    @Test
    void defaultsAndMalformedNumbers() throws Exception {
        AppConfig config = AppConfig.load(dir.resolve("missing.properties"), Map.of(), new String[] {"--bus.capacity=lots"});
        assertEquals(AppConfig.DEFAULT_BUS_CAPACITY, config.getInt(AppConfig.BUS_CAPACITY, AppConfig.DEFAULT_BUS_CAPACITY));
        assertEquals("fallback", config.get("unknown.key", "fallback"));
    }

    @Test
    void secretsAreIgnored() throws Exception {
        Path file = dir.resolve(AppPaths.CONFIG_FILE);
        Files.writeString(file, "claude.api.key=sk-should-not-be-here\n");
        AppConfig config = AppConfig.load(file, Map.of("AEGISLENS_GEMINI_API_KEY", "x"), new String[] {"--vt.token=y"});
        assertEquals("none", config.get("claude.api.key", "none"));
        assertEquals("none", config.get("gemini.api.key", "none"));
        assertEquals("none", config.get("vt.token", "none"));
    }

    @Test
    void dataDirCanBeChosen() throws Exception {
        AppConfig config = AppConfig.load(null, Map.of(), new String[] {"--data.dir=" + dir.resolve("data")});
        assertEquals(dir.resolve("data").toAbsolutePath().normalize(), config.paths().dataDir());
        assertTrue(AppConfig.defaults().paths().dataDir().endsWith(AppPaths.FOLDER_NAME));
    }
}
