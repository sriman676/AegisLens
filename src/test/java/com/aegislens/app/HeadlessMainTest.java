package com.aegislens.app;

import com.aegislens.TestWait;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.ui.Launcher;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/** R12: headless start against a live log, clean shutdown, version and configuration checks. */
class HeadlessMainTest {

    @TempDir
    Path dir;

    /**
     * Loads SQLite's native library once from the default temp folder. Otherwise the first open in this JVM extracts it
     * into the data folder's tmp (AppDatabase hardening), and Windows cannot delete a loaded DLL when @TempDir cleans up.
     */
    @BeforeAll
    static void loadSqliteOutsideTheTempDir() throws Exception {
        Database.inMemory().close();
    }

    @Test
    void headlessRunDetectsAnAppendedAttackAndStopsWithoutLeftoverThreads() throws Exception {
        Path log = Files.writeString(dir.resolve("auth.log"), "");
        AppConfig cfg = AppConfig.load(null, Map.of(), new String[] {"--data.dir=" + dir.resolve("data"),
                "--monitor.ssh.files=" + log, "--monitor.start.at.beginning=true", "--feeds.enabled=false", "--oddhour.zone=UTC", "--monitor.silence.minutes=0"});
        assertEquals(List.of(), HeadlessMain.problems(cfg));
        HeadlessMain.Running running = HeadlessMain.start(cfg);
        try {
            TestWait.until(() -> running.coordinator().monitorStatus().size() == 1, "the tailer did not start");
            StringBuilder attack = new StringBuilder();
            for (int i = 0; i < 6; i++) {
                attack.append("Oct 21 02:14:0").append(i).append(" srv sshd[1]: Failed password for root from 203.0.113.45 port ")
                        .append(50000 + i).append(" ssh2\n");
            }
            Files.writeString(log, attack, StandardOpenOption.APPEND);
            FindingRepository findings = new FindingRepository(running.coordinator().database());
            TestWait.until(() -> count(findings) > 0, "no finding was saved");
        } finally {
            running.stop();                                  // what the shutdown hook runs
        }
        running.awaitStop();
        assertEquals(List.of(), Thread.getAllStackTraces().keySet().stream().filter(Thread::isAlive)
                .map(Thread::getName).filter(n -> n.startsWith(ScanCoordinator.THREAD_PREFIX)).toList(), "leftover threads");
    }

    @Test
    void versionMatchesThePomAndCheckConfigReportsProblems() throws Exception {
        Matcher m = Pattern.compile("<artifactId>aegislens</artifactId>\\s*<version>([^<]+)</version>")
                .matcher(Files.readString(Path.of("pom.xml")));
        assertTrue(m.find());
        assertEquals(m.group(1), HeadlessMain.VERSION);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream print = new PrintStream(out, true, StandardCharsets.UTF_8);
        assertEquals(HeadlessMain.OK, HeadlessMain.run(new String[] {"--version"}, print, print));
        assertTrue(out.toString(StandardCharsets.UTF_8).startsWith("AegisLens " + HeadlessMain.VERSION));

        String[] bad = {"--check-config", "--data.dir=" + dir.resolve("d"), "--syslog.udp.port=99999",
                "--oddhour.zone=Mars/Base", "--oddhour.start=22", "--scan.threads=many", "--monitor.ssh.files=" + dir.resolve("missing.log")};
        out.reset();
        assertEquals(HeadlessMain.BAD_CONFIG, HeadlessMain.run(bad, print, print));
        String text = out.toString(StandardCharsets.UTF_8);
        for (String expected : List.of("syslog.udp.port", "Mars/Base", "oddhour.start", "scan.threads", "missing.log")) {
            assertTrue(text.contains(expected), "reports " + expected + ": " + text);
        }
        assertEquals(HeadlessMain.BAD_CONFIG, HeadlessMain.run(new String[] {"--config"}, print, print), "--config needs a file");
        assertEquals(HeadlessMain.OK, HeadlessMain.run(new String[] {"--check-config", "--data.dir=" + dir.resolve("d")}, print, print));
    }

    @Test
    void launcherRecognisesHeadlessFlags() {
        assertTrue(Launcher.wantsHeadless(new String[] {"--headless"}));
        assertTrue(Launcher.wantsHeadless(new String[] {"--data.dir=x", "--check-config"}));
        assertFalse(Launcher.wantsHeadless(new String[] {"--data.dir=x"}));
    }

    private static int count(FindingRepository repo) {
        try {
            return repo.count();
        } catch (Exception e) {
            return 0;
        }
    }

}
