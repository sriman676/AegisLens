package com.aegislens.db;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Startup safety: instance lock, corrupt-file recovery, temp folder and permissions. */
class AppDatabaseTest {

    @TempDir
    Path dir;

    @Test
    void secondInstanceIsRefusedUntilTheFirstCloses() throws Exception {
        try (AppDatabase first = AppDatabase.open(dir)) {
            assertTrue(first.warning().isEmpty());
            AlreadyRunningException e = assertThrows(AlreadyRunningException.class, () -> AppDatabase.open(dir));
            assertTrue(e.getMessage().contains("already running"));
        }
        try (AppDatabase again = AppDatabase.open(dir)) {
            assertNotNull(again.database());
        }
    }

    @Test
    void corruptFileIsMovedAsideAndAFreshDatabaseIsCreated() throws Exception {
        byte[] garbage = new byte[8192];
        for (int i = 0; i < garbage.length; i++) {
            garbage[i] = (byte) ('A' + i % 26);
        }
        Files.write(dir.resolve(AppDatabase.DB_FILE), garbage);
        try (AppDatabase app = AppDatabase.open(dir)) {
            assertTrue(app.warning().isPresent());
            assertEquals(27, new RuleRepository(app.database()).findAll().size(), "fresh database with seed rules");
        }
        try (var files = Files.list(dir)) {
            assertTrue(files.anyMatch(p -> p.getFileName().toString().startsWith(AppDatabase.DB_FILE + ".corrupt-")));
        }
    }

    @Test
    void sqliteTempFolderPointsIntoTheDataFolderWhenNotSet() throws Exception {
        String before = System.getProperty(AppDatabase.TMPDIR_PROPERTY);
        try {
            System.clearProperty(AppDatabase.TMPDIR_PROPERTY);
            AppDatabase.useTempFolderIn(dir);
            assertEquals(dir.resolve("tmp").toAbsolutePath().toString(), System.getProperty(AppDatabase.TMPDIR_PROPERTY));
            assertTrue(Files.isDirectory(dir.resolve("tmp")));
            AppDatabase.useTempFolderIn(dir.resolve("other"));
            assertEquals(dir.resolve("tmp").toAbsolutePath().toString(), System.getProperty(AppDatabase.TMPDIR_PROPERTY),
                    "an explicit setting is never overwritten");
        } finally {
            if (before == null) {
                System.clearProperty(AppDatabase.TMPDIR_PROPERTY);
            } else {
                System.setProperty(AppDatabase.TMPDIR_PROPERTY, before);
            }
        }
    }

    @Test
    void databaseFileIsOwnerOnlyOnPosixSystems() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"), "POSIX permissions only (Linux, macOS)");
        Path data = dir.resolve("data");
        try (AppDatabase app = AppDatabase.open(data)) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(data.resolve(AppDatabase.DB_FILE))));
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(data)));
        }
        Path shared = Files.createDirectories(dir.resolve("shared"));
        Files.setPosixFilePermissions(shared, PosixFilePermissions.fromString("rwxr-xr-x"));
        try (AppDatabase app = AppDatabase.open(shared)) {
            assertEquals("rwxr-xr-x", PosixFilePermissions.toString(Files.getPosixFilePermissions(shared)),
                    "a folder we did not create keeps its permissions");
        }
    }
}
