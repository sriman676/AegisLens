package com.aegislens.sandbox;

import com.aegislens.core.AnalysisException;
import com.aegislens.sandbox.demo.DemoMain;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * "Sandbox Lab": runs ONE of our own harmless DemoProgram values in a separate JVM process and watches it.
 *
 * What this isolates (pure Java, same code on every OS): separate process, empty environment (so API keys cannot leak),
 * private scratch directory deleted afterwards, heap limit, hard timeout, output cap, no stdin.
 * What it does NOT isolate: file access outside the scratch directory and network access. So it must never be pointed
 * at unknown files, and the type system enforces that: run() takes a DemoProgram enum, not a path.
 * For unknown files use ContainerSandbox.
 */
public class LocalSandbox {

    private final SandboxPolicy policy;

    public LocalSandbox(SandboxPolicy policy) {
        this.policy = policy;
    }

    public LocalSandbox() {
        this(SandboxPolicy.defaults());
    }

    public SandboxReport run(DemoProgram demo) throws AnalysisException {
        Path scratch = null;
        try {
            scratch = Files.createTempDirectory("aegislens-sbx-");

            List<String> command = new ArrayList<>();
            command.add(javaExecutable());
            command.add("-Xmx" + policy.maxHeapMb() + "m");
            command.add("-XX:-UsePerfData");                       // stops the JVM writing its own files into the scratch dir
            command.add("-Djava.io.tmpdir=" + scratch);
            command.add("-cp");
            command.add(absoluteClassPath());
            command.add(DemoMain.class.getName());
            command.add(demo.id());

            ProcessBuilder builder = new ProcessBuilder(command).directory(scratch.toFile()).redirectErrorStream(true);
            Map<String, String> env = builder.environment();
            String systemRoot = env.get("SystemRoot");             // Windows needs this to start a JVM
            env.clear();
            if (systemRoot != null) {
                env.put("SystemRoot", systemRoot);
            }

            long start = System.nanoTime();
            Process process = builder.start();
            OutputCollector.Watched w = OutputCollector.watch(process, start, policy,
                    () -> process.descendants().forEach(ProcessHandle::destroyForcibly));
            return new SandboxReport("local-demo", demo.id(), w.finished() ? process.exitValue() : null, !w.finished(), false,
                    w.millis(), w.text(), w.truncated(), listFiles(scratch));
        } catch (IOException e) {
            throw new AnalysisException("Local sandbox could not run " + demo.id(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AnalysisException("Local sandbox was interrupted", e);
        } finally {
            deleteQuietly(scratch);
        }
    }

    /**
     * The java command of the runtime we run on. Not the current process's command: in the packaged app that is the
     * AegisLens launcher, which does not accept JVM options.
     */
    static String javaExecutable() throws AnalysisException {
        Path bin = Path.of(System.getProperty("java.home"), "bin");
        for (String name : List.of("java", "java.exe")) {
            if (Files.isExecutable(bin.resolve(name))) {
                return bin.resolve(name).toString();
            }
        }
        throw new AnalysisException("This runtime has no java command (" + bin + "), so the demo programs cannot start. "
                + "Run AegisLens from the JAR, or package it with deploy/package-app-image, which keeps the command.");
    }

    /**
     * Our class path with every entry made absolute: the demo runs in the scratch directory, so a relative entry such as
     * "target/aegislens-1.0.0.jar" (java -jar from the project folder) would point nowhere.
     */
    static String absoluteClassPath() {
        List<String> entries = new ArrayList<>();
        for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
            if (!entry.isBlank()) {
                entries.add(Path.of(entry).toAbsolutePath().toString());
            }
        }
        return String.join(File.pathSeparator, entries);
    }

    static List<String> listFiles(Path root) throws IOException {
        try (Stream<Path> walk = Files.walk(root)) {
            return walk.filter(Files::isRegularFile)
                    .map(p -> root.relativize(p).toString().replace('\\', '/'))
                    .sorted()
                    .toList();
        }
    }

    static void deleteQuietly(Path root) {
        if (root == null) {
            return;
        }
        try (Stream<Path> walk = Files.walk(root)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (IOException ignored) {
            // best effort: it is a temp directory
        }
    }
}
