package com.aegislens.sandbox;

import com.aegislens.core.AnalysisException;
import com.aegislens.core.Finding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class SandboxTest {

    @TempDir
    Path dir;

    private static List<String> ruleIds(List<Finding> findings) {
        return findings.stream().map(Finding::ruleId).collect(Collectors.toList());
    }

    // ---------- LocalSandbox: really starts a child JVM ----------

    @Test
    void helloRunsCleanly() throws AnalysisException {
        SandboxReport r = new LocalSandbox().run(DemoProgram.HELLO);
        assertEquals(Integer.valueOf(0), r.exitCode());
        assertFalse(r.timedOut());
        assertTrue(r.output().contains("hello from the sandbox"));
        assertTrue(r.createdFiles().isEmpty());
        assertTrue(BehaviourFindings.from(r).isEmpty());
    }

    @Test
    void dropperFilesAreSeenAndScratchIsCleanedUp() throws AnalysisException {
        SandboxReport r = new LocalSandbox().run(DemoProgram.DROPPER);
        assertEquals(List.of("dropped_1.txt", "dropped_2.txt", "dropped_3.txt"), r.createdFiles());
        List<Finding> findings = BehaviourFindings.from(r);
        assertEquals(List.of("SBX-001"), ruleIds(findings));
        assertEquals(60, findings.get(0).score());
    }

    @Test
    void burnerIsKilledAtTheTimeout() throws AnalysisException {
        SandboxPolicy policy = SandboxPolicy.defaults().withTimeout(Duration.ofSeconds(2));
        SandboxReport r = new LocalSandbox(policy).run(DemoProgram.BURNER);
        assertTrue(r.timedOut());
        assertEquals(null, r.exitCode());
        assertTrue(r.durationMs() < 15_000, "must not run much longer than the limit but was " + r.durationMs());
        assertEquals(List.of("SBX-002"), ruleIds(BehaviourFindings.from(r)));
    }

    @Test
    void outputIsCapped() throws AnalysisException {
        SandboxPolicy policy = SandboxPolicy.defaults().withMaxOutputBytes(2048);
        SandboxReport r = new LocalSandbox(policy).run(DemoProgram.CHATTY);
        assertTrue(r.outputTruncated());
        assertTrue(r.output().length() <= 2048);
        assertEquals(Integer.valueOf(0), r.exitCode(), "the child must finish even though we discard its output");
        assertTrue(ruleIds(BehaviourFindings.from(r)).contains("SBX-003"));
    }

    @Test
    void crashIsReported() throws AnalysisException {
        SandboxReport r = new LocalSandbox().run(DemoProgram.CRASH);
        assertEquals(Integer.valueOf(1), r.exitCode());
        assertTrue(r.output().contains("simulated crash"));
        assertEquals(List.of("SBX-004"), ruleIds(BehaviourFindings.from(r)));
    }

    @Test
    void childCannotSeeTheParentsEnvironment() throws AnalysisException {
        SandboxReport r = new LocalSandbox().run(DemoProgram.ENV);
        assertTrue(r.output().contains("pathVisible=false"), "env must be empty but output was: " + r.output());
        assertTrue(r.output().contains("apiKeyVisible=false"));
    }

    @Test
    void analyzerReturnsFindings() throws AnalysisException {
        assertEquals(List.of("SBX-001"), ruleIds(new SandboxAnalyzer().analyze(DemoProgram.DROPPER)));
    }

    @Test
    void policyRejectsUnsafeValues() {
        assertThrows(IllegalArgumentException.class, () -> new SandboxPolicy(Duration.ZERO, 4096, 32, 128, 0.5, 64));
        assertThrows(IllegalArgumentException.class, () -> new SandboxPolicy(Duration.ofHours(1), 4096, 32, 128, 0.5, 64));
        assertThrows(IllegalArgumentException.class, () -> new SandboxPolicy(Duration.ofSeconds(5), 4096, 32, 128, 8, 64));
        assertThrows(IllegalArgumentException.class, () -> new SandboxPolicy(Duration.ofSeconds(5), 4096, 32, 128, 0.5, 100_000));
    }

    // ---------- ContainerSandbox: pure parts and guards (no Docker needed) ----------

    @Test
    void createCommandContainsEveryIsolationFlagAndNothingDangerous() throws Exception {
        Path sample = dir.resolve("sample");
        Files.write(sample, new byte[]{1, 2, 3});
        List<String> cmd = ContainerSandbox.buildCreateCommand("docker", "debian:12-slim", "aegislens-sbx-test", sample,
                SandboxPolicy.defaults(), ContainerSandbox.entryFor("evil.sh"));

        String joined = String.join(" ", cmd);
        assertEquals("docker", cmd.get(0));
        assertEquals("create", cmd.get(1));
        assertTrue(joined.contains("--network none"));
        assertTrue(joined.contains("--cap-drop ALL"));
        assertTrue(joined.contains("--security-opt no-new-privileges"));
        assertTrue(joined.contains("--pids-limit 64"));
        assertTrue(joined.contains("--memory 128m"));
        assertTrue(joined.contains("--memory-swap 128m"), "swap must equal memory so it cannot swap past the limit");
        assertTrue(joined.contains("--cpus 0.5"));
        assertTrue(joined.contains("--user 65534:65534"), "must not run as root");
        assertTrue(joined.contains("target=/sandbox/sample,readonly"), "sample must be mounted read-only");
        assertTrue(joined.endsWith("debian:12-slim sh /sandbox/sample"));

        for (String forbidden : new String[]{"--privileged", "--cap-add", "--net=host", "--network host", "--pid=host",
                "--ipc=host", " -e ", "--env", "/var/run/docker.sock", "--device"}) {
            assertFalse(joined.contains(forbidden), "forbidden option present: " + forbidden);
        }
        assertEquals(1L, cmd.stream().filter(s -> s.equals("--mount")).count(), "only the read-only sample may be mounted");
    }

    @Test
    void sampleNamesCannotInjectMountOptions() {
        Path evil = Path.of("/tmp/a,source=/etc,target=/x/sample");
        assertThrows(AnalysisException.class, () -> ContainerSandbox.buildCreateCommand("docker", "img", "n", evil,
                SandboxPolicy.defaults(), List.of("/sandbox/sample")));
    }

    @Test
    void entryChoosesInterpreterByExtension() {
        assertEquals(List.of("sh", "/sandbox/sample"), ContainerSandbox.entryFor("x.SH"));
        assertEquals(List.of("python3", "/sandbox/sample"), ContainerSandbox.entryFor("x.py"));
        assertEquals(List.of("/sandbox/sample"), ContainerSandbox.entryFor("x.elf"));
    }

    @Test
    void diffParserKeepsOnlyAddedFiles() {
        List<String> files = ContainerSandbox.parseDiff(List.of("C /tmp", "A /tmp/payload.bin", "D /etc/x", "A /tmp/a.txt", ""));
        assertEquals(List.of("/tmp/a.txt", "/tmp/payload.bin"), files);
        assertEquals(List.of("/tmp/x"), ContainerSandbox.parseDiff(List.of("A /sandbox", "A /sandbox/sample", "A /tmp/x")),
                "our own mount point must not be reported as a dropped file");
        assertEquals(Integer.valueOf(137), ContainerSandbox.parseExit("137 true\n"));
        assertEquals(null, ContainerSandbox.parseExit("garbage"));
    }

    @Test
    void realSandboxIsOffUnlessExplicitlyEnabled() throws IOException {
        Path sample = dir.resolve("s.bin");
        Files.write(sample, new byte[]{1});
        ContainerSandbox disabled = new ContainerSandbox("docker", "img", SandboxPolicy.defaults(), false);
        AnalysisException e = assertThrows(AnalysisException.class, () -> disabled.run(sample));
        assertTrue(e.getMessage().contains(ContainerSandbox.ENABLE_ENV));
    }

    @Test
    void enabledSandboxStillValidatesInputAndEngine() throws IOException {
        ContainerSandbox box = new ContainerSandbox("no-such-container-engine", "img", SandboxPolicy.defaults(), true);
        assertThrows(AnalysisException.class, () -> box.run(dir.resolve("missing")));             // no such file
        assertThrows(AnalysisException.class, () -> box.run(dir));                                // a directory
        Path empty = dir.resolve("empty");
        Files.write(empty, new byte[0]);
        assertThrows(AnalysisException.class, () -> box.run(empty));                              // empty
        Path ok = dir.resolve("ok");
        Files.write(ok, new byte[]{1, 2, 3});
        AnalysisException e = assertThrows(AnalysisException.class, () -> box.run(ok));           // engine missing
        assertTrue(e.getMessage().contains("not installed"));
        assertFalse(box.engineAvailable());
    }
}
