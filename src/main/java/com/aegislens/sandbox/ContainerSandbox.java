package com.aegislens.sandbox;

import com.aegislens.core.AnalysisException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * The REAL sandbox: the same Java code on Windows, Linux and macOS controls Docker or Podman, and the container engine
 * provides the isolation (the JVM cannot). A sample runs in a throw-away Linux container with
 *   no network, all capabilities dropped, no privilege escalation, non-root user, memory/CPU/process limits,
 *   the sample mounted READ-ONLY, no environment variables, and the container destroyed afterwards.
 * We then read exit code, output, memory kills and the files the sample created (engine "diff").
 *
 * SAFETY (read the README section "Security and safety" before enabling):
 *  - Disabled unless the environment variable AEGISLENS_ENABLE_REAL_SANDBOX=1 is set.
 *  - A container shares the host kernel, so it is NOT a perfect boundary. Use a disposable VM for real malware.
 *  - Linux containers run Linux samples (ELF, shell scripts), not Windows .exe files.
 *  - The Java side only ever calls the engine binary; it never runs the sample itself.
 */
public class ContainerSandbox {

    public static final String ENABLE_ENV = "AEGISLENS_ENABLE_REAL_SANDBOX";
    public static final String DEFAULT_IMAGE = "debian:12-slim";
    public static final long MAX_SAMPLE_BYTES = 10L * 1024 * 1024;

    private final String engine;
    private final String image;
    private final SandboxPolicy policy;
    private final boolean enabled;

    public ContainerSandbox(String engine, String image, SandboxPolicy policy, boolean enabled) {
        this.engine = engine;
        this.image = image;
        this.policy = policy;
        this.enabled = enabled;
    }

    /** Reads AEGISLENS_ENABLE_REAL_SANDBOX, AEGISLENS_CONTAINER_ENGINE (docker or podman) and AEGISLENS_SANDBOX_IMAGE. */
    public static ContainerSandbox fromEnvironment() {
        boolean enabled = "1".equals(System.getenv(ENABLE_ENV));
        String engine = System.getenv("AEGISLENS_CONTAINER_ENGINE");
        if (!"podman".equals(engine)) {
            engine = "docker";
        }
        String image = System.getenv("AEGISLENS_SANDBOX_IMAGE");
        return new ContainerSandbox(engine, image == null || image.isBlank() ? DEFAULT_IMAGE : image,
                SandboxPolicy.defaults(), enabled);
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** True if the engine binary exists and its server answers. */
    public boolean engineAvailable() {
        try {
            return exec(List.of(engine, "version", "--format", "{{.Server.Version}}"), Duration.ofSeconds(10)).exit() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    public SandboxReport run(Path sample) throws AnalysisException {
        if (!enabled) {
            throw new AnalysisException("The real sandbox is disabled. Read the README section \"Security and safety\", then set "
                    + ENABLE_ENV + "=1 inside a disposable VM.");
        }
        validate(sample);
        if (!engineAvailable()) {
            throw new AnalysisException(engine + " is not installed or not running");
        }

        String name = "aegislens-sbx-" + UUID.randomUUID().toString().substring(0, 8);
        Path hostDir = null;
        boolean created = false;
        try {
            hostDir = Files.createTempDirectory("aegislens-sbx-");
            Path copy = hostDir.resolve("sample");
            Files.copy(sample, copy);
            copy.toFile().setReadable(true, false);
            copy.toFile().setExecutable(true, false);

            Result create = exec(buildCreateCommand(engine, image, name, copy, policy, entryFor(sample.getFileName().toString())),
                    Duration.ofSeconds(60));
            if (create.exit() != 0) {
                throw new AnalysisException("Could not create the container: " + firstLine(create.output()));
            }
            created = true;

            long start = System.nanoTime();
            Process process = new ProcessBuilder(engine, "start", "-a", name).redirectErrorStream(true).start();
            OutputCollector.Watched w = OutputCollector.watch(process, start, policy,
                    () -> exec(List.of(engine, "kill", name), Duration.ofSeconds(15)));
            boolean finished = w.finished();

            Result inspect = exec(List.of(engine, "inspect", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}", name),
                    Duration.ofSeconds(15));
            Integer exitCode = finished ? parseExit(inspect.output()) : null;
            boolean oom = inspect.output().trim().endsWith("true");

            Result diff = exec(List.of(engine, "diff", name), Duration.ofSeconds(15));
            List<String> files = parseDiff(diff.output().lines().toList());

            return new SandboxReport("container", sample.getFileName().toString(), exitCode, !finished, oom, w.millis(),
                    w.text(), w.truncated(), files);
        } catch (IOException e) {
            throw new AnalysisException("Container sandbox failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AnalysisException("Container sandbox was interrupted", e);
        } finally {
            if (created) {
                try {
                    exec(List.of(engine, "rm", "-f", name), Duration.ofSeconds(30));
                } catch (IOException e) {
                    // nothing more we can do; the name is unique so it cannot clash later
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            LocalSandbox.deleteQuietly(hostDir);
        }
    }

    // ---- pure helpers (unit-tested without Docker) ----

    /**
     * Every isolation flag lives here, in one place, so a test can check them.
     * Deliberately absent: --privileged, --network (other than none), -e (environment), -v/--mount (other than the read-only sample), --cap-add.
     */
    static List<String> buildCreateCommand(String engine, String image, String name, Path hostSample,
                                           SandboxPolicy policy, List<String> entry) throws AnalysisException {
        String source = hostSample.toAbsolutePath().toString();
        if (source.contains(",") || source.contains("\"")) {
            throw new AnalysisException("Sample path must not contain commas or quotes");
        }
        List<String> command = new ArrayList<>(List.of(
                engine, "create", "--name", name,
                "--network", "none",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", Integer.toString(policy.pidsLimit()),
                "--memory", policy.containerMemoryMb() + "m",
                "--memory-swap", policy.containerMemoryMb() + "m",
                "--cpus", String.valueOf(policy.containerCpus()),
                "--user", "65534:65534",
                "--workdir", "/tmp",
                "--mount", "type=bind,source=" + source + ",target=/sandbox/sample,readonly",
                image));
        command.addAll(entry);
        return command;
    }

    /** How to start a sample: shell scripts and Python scripts through their interpreter, everything else directly. */
    static List<String> entryFor(String fileName) {
        String lower = fileName.toLowerCase();
        if (lower.endsWith(".sh")) {
            return List.of("sh", "/sandbox/sample");
        }
        if (lower.endsWith(".py")) {
            return List.of("python3", "/sandbox/sample");
        }
        return List.of("/sandbox/sample");
    }

    /**
     * "docker diff" prints lines such as "A /tmp/x" (added), "C /tmp" (changed), "D /y" (deleted). We keep the added files,
     * except the mount point of our own read-only sample: the engine creates /sandbox and /sandbox/sample in the container
     * layer, and a real run on Docker 29 showed them as "A" lines, which would be reported as files the sample dropped.
     */
    static List<String> parseDiff(List<String> lines) {
        return lines.stream()
                .map(String::trim)
                .filter(l -> l.startsWith("A "))
                .map(l -> l.substring(2).trim())
                .filter(path -> !path.equals("/sandbox") && !path.equals("/sandbox/sample"))
                .sorted()
                .toList();
    }

    static Integer parseExit(String inspectOutput) {
        try {
            return Integer.parseInt(inspectOutput.trim().split("\\s+")[0]);
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
            return null;
        }
    }

    private static void validate(Path sample) throws AnalysisException {
        try {
            if (!Files.isRegularFile(sample)) {
                throw new AnalysisException("Not a regular file: " + sample.getFileName());
            }
            long size = Files.size(sample);
            if (size == 0 || size > MAX_SAMPLE_BYTES) {
                throw new AnalysisException("Sample must be between 1 byte and " + (MAX_SAMPLE_BYTES / (1024 * 1024)) + " MB");
            }
        } catch (IOException e) {
            throw new AnalysisException("Could not read " + sample.getFileName(), e);
        }
    }

    private record Result(int exit, String output) {
    }

    /** Runs one short engine command (create, kill, inspect, diff, rm) and returns its exit code and capped output. */
    private static Result exec(List<String> command, Duration timeout) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        process.getOutputStream().close();
        OutputCollector collector = new OutputCollector(process.getInputStream(), 64 * 1024);
        Thread reader = new Thread(collector, "engine-output");
        reader.setDaemon(true);
        reader.start();
        if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
            process.destroyForcibly();
            reader.join(2000);
            return new Result(-1, collector.text());
        }
        reader.join(5000);
        return new Result(process.exitValue(), collector.text());
    }

    private static String firstLine(String text) {
        return text.lines().findFirst().orElse("no details");
    }
}
