package com.aegislens.app;

import com.aegislens.TestWait;
import com.aegislens.core.CorruptFileException;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.intrusion.LogType;
import com.aegislens.malware.ScanResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Edge cases: odd files (empty: refused with a reason, 1 byte, a text file named .exe) and a folder whose name has spaces and
 * non-ASCII characters go through the real app (scan, folder scan, log replay) without an error.
 */
class EdgeCaseInputTest {

    @TempDir
    Path dir;

    /** Loads SQLite's native library outside the temp folder (see HeadlessMainTest). */
    @BeforeAll
    static void loadSqlite() throws Exception {
        Database.inMemory().close();
    }

    @Test
    void oddFilesAndUnusualPathsWork() throws Exception {
        Path folder = Files.createDirectories(dir.resolve("Prüfung mit Leerzeichen 日本 é"));
        Path empty = Files.write(folder.resolve("empty file.bin"), new byte[0]);
        Path oneByte = Files.write(folder.resolve("one byte.dat"), new byte[] {0x4D});
        Path fakeExe = Files.writeString(folder.resolve("rechnung ü.exe"), "just some text, not a program\n");
        Path log = Files.copy(Path.of("sample-data", "auth.log"), folder.resolve("auth ü.log"));

        ScanCoordinator c = new ScanCoordinator(AppConfig.load(null, Map.of(), new String[] {
                "--data.dir=" + dir.resolve("daten ö"), "--feeds.enabled=false", "--oddhour.zone=UTC"}));
        c.start();
        try {
            ExecutionException refused = assertThrows(ExecutionException.class, () -> c.scanFile(empty).get(30, TimeUnit.SECONDS));
            assertInstanceOf(CorruptFileException.class, refused.getCause());
            assertTrue(refused.getCause().getMessage().contains("empty"), "a readable reason, not a crash");
            for (Path file : List.of(oneByte, fakeExe)) {
                ScanResult r = c.scanFile(file).get(30, TimeUnit.SECONDS);
                assertEquals(file.getFileName().toString(), r.name(), "the name survives unchanged");
                assertTrue(r.risk() >= 0 && r.risk() <= 100, file + ": " + r.risk());
            }
            assertNotEquals("PE", c.scanFile(fakeExe).get(30, TimeUnit.SECONDS).fileType(),
                    "the type comes from the bytes, not from the .exe name");
            List<ScanResult> all = c.scanFolder(folder, false).get(30, TimeUnit.SECONDS);
            System.out.println("folder scan: " + all.stream().map(ScanResult::name).toList());
            assertTrue(all.size() >= 3, "the empty file does not stop the folder scan: " + all);
            c.replayLog(log, LogType.SSH).get(30, TimeUnit.SECONDS);
            FindingRepository findings = new FindingRepository(c.database());
            TestWait.until(() -> {
                try {
                    return !findings.findByRule("NET-001", 1).isEmpty();
                } catch (SQLException e) {
                    return false;
                }
            }, "brute force found in a log whose path has spaces and non-ASCII characters");
        } finally {
            c.shutdown();
        }
    }
}
