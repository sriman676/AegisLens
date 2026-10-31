package com.aegislens.app;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class AppPathsAndLoggingTest {

    @TempDir
    Path dir;

    @AfterEach
    void removeHandler() {
        LoggingSetup.uninstall();
    }

    @Test
    void pathsLiveInsideTheDataFolder() {
        AppPaths paths = new AppPaths(dir.resolve("x").resolve("..").resolve("data"));
        assertEquals(dir.resolve("data").toAbsolutePath(), paths.dataDir());
        assertEquals(paths.dataDir().resolve("aegislens.properties"), paths.configFile());
        assertEquals(paths.dataDir(), paths.logsDir().getParent());
        assertEquals(paths.dataDir(), paths.backupsDir().getParent());
        assertEquals(AppPaths.FOLDER_NAME, AppPaths.defaultPaths().dataDir().getFileName().toString());
    }

    @Test
    void loggingWritesARotatingFileOnce() throws Exception {
        Path logs = dir.resolve("logs");
        LoggingSetup.install(logs);
        LoggingSetup.install(logs);                         // second call does nothing
        assertTrue(LoggingSetup.isInstalled());
        Logger.getLogger("com.aegislens.test").info("hello log");
        LoggingSetup.uninstall();                           // flushes and closes the file
        String text = Files.readString(logs.resolve("aegislens-0.log"));
        assertTrue(text.contains("hello log"));
    }
}
