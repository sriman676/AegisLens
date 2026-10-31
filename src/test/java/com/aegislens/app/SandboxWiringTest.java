package com.aegislens.app;

import com.aegislens.core.Finding;
import com.aegislens.db.Database;
import com.aegislens.sandbox.DemoProgram;
import com.aegislens.sandbox.SandboxReport;
import com.aegislens.ui.SandboxPresenter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** P9 wiring: demos run through the app and publish SBX findings; the container stays off without the variable. */
class SandboxWiringTest {

    @TempDir
    Path dir;

    @Test
    void theDropperDemoCreatesFilesAndRaisesSbx001() throws Exception {
        try (Database db = Database.inMemory()) {
            ScanCoordinator c = new ScanCoordinator(db, AppConfig.defaults());
            c.start();
            try {
                ScanCoordinator.SandboxRun r = c.runDemo(DemoProgram.DROPPER).get(60, TimeUnit.SECONDS);
                assertEquals(3, r.report().createdFiles().size(), r.report().toString());
                assertEquals(List.of("SBX-001"), r.findings().stream().map(Finding::ruleId).toList());
                assertEquals(60, r.findings().get(0).score());
                assertTrue(SandboxPresenter.summary(r.report()).startsWith("exit 0 after "));

                assertEquals("off", c.containerState(), "AEGISLENS_ENABLE_REAL_SANDBOX is not set in tests");
                Path sample = Files.writeString(dir.resolve("sample.sh"), "echo hi\n");
                ExecutionException e = assertThrows(ExecutionException.class,
                        () -> c.runInContainer(sample).get(30, TimeUnit.SECONDS));
                assertTrue(e.getCause().getMessage().contains(com.aegislens.sandbox.ContainerSandbox.ENABLE_ENV), e.getCause().getMessage());
            } finally {
                c.shutdown();
            }
        }
    }

    @Test
    void presenterTexts() {
        SandboxReport timedOut = new SandboxReport("local-demo", "burner", null, true, false, 5003, "", false, List.of());
        assertEquals("stopped: time limit reached after 5003 ms  ·  0 file(s) created", SandboxPresenter.summary(timedOut));
        assertTrue(SandboxPresenter.containerText("off").contains("AEGISLENS_ENABLE_REAL_SANDBOX=1"));
        assertTrue(SandboxPresenter.containerText("ready").contains("disposable VM"));
    }
}
