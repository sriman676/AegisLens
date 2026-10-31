package com.aegislens.app;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Customisation: start-up options saved from Settings keep the file readable, valid and secret-free. */
class ConfigFileWriterTest {

    @TempDir
    Path dir;

    @Test
    void changedKeysAreRewrittenInPlaceCommentsKeptNewKeysAppended() throws Exception {
        Path file = Files.writeString(dir.resolve("aegislens.properties"),
                "# my notes\noddhour.start=22:00\n\n# AI\nai.budget.hour=30\n");
        Path log = Files.writeString(dir.resolve("auth.log"), "");
        Map<String, String> changes = new LinkedHashMap<>();
        changes.put("oddhour.start", "21:30");
        changes.put("ai.budget.hour", "");                       // blank: back to the default
        changes.put("monitor.ssh.files", log.toString());        // on Windows this path has backslashes
        assertEquals(List.of(), ConfigFileWriter.update(file, changes, dir.resolve("data")));

        String text = Files.readString(file);
        assertTrue(text.startsWith("# my notes\noddhour.start=21:30\n"), text);
        assertTrue(text.contains("# AI\n"), "comments are kept");
        assertFalse(text.contains("ai.budget.hour"), "a blank value removes the line");
        Map<String, String> read = ConfigFileWriter.read(file);
        assertEquals(log.toString(), read.get("monitor.ssh.files"), "backslashes survive the round trip");
        assertEquals("21:30", read.get("oddhour.start"));
    }

    @Test
    void anInvalidValueLeavesTheFileUntouched() throws Exception {
        Path file = Files.writeString(dir.resolve("aegislens.properties"), "syslog.udp.port=-1\n");
        List<String> problems = ConfigFileWriter.update(file, Map.of("syslog.udp.port", "99999", "oddhour.end", "6"),
                dir.resolve("data"));
        assertEquals(2, problems.size(), problems.toString());
        assertEquals("syslog.udp.port=-1\n", Files.readString(file));
        try (var files = Files.list(dir)) {
            assertEquals(1, files.count(), "no temporary file is left behind");
        }
    }

    @Test
    void secretsAndOddKeysAreRefusedAndValuesEscaped() throws Exception {
        Path file = dir.resolve("aegislens.properties");
        assertFalse(ConfigFileWriter.update(file, Map.of("claude.api.key", "sk-x"), dir).isEmpty());
        assertFalse(ConfigFileWriter.update(file, Map.of("x=y\nz", "1"), dir).isEmpty());
        assertFalse(Files.exists(file));
        String backslash = String.valueOf((char) 92);
        assertEquals("C:" + backslash + backslash + "logs", ConfigFileWriter.escape("C:" + backslash + "logs"), "doubled");
        assertEquals(backslash + "u4e2d", ConfigFileWriter.escape(String.valueOf((char) 0x4e2d)), "non-Latin-1 escaped");
    }
}
