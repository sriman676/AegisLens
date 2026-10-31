package com.aegislens.sandbox;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/** The demo runs in a scratch directory, so it must get absolute class-path entries and a real java command. */
class LocalSandboxPathTest {

    @Test
    void classPathEntriesAreAbsoluteAndJavaIsTheRuntimesOwnCommand() throws Exception {
        for (String entry : LocalSandbox.absoluteClassPath().split(File.pathSeparator)) {
            assertTrue(Path.of(entry).isAbsolute(), entry);
        }
        Path java = Path.of(LocalSandbox.javaExecutable());
        assertTrue(Files.isExecutable(java), java.toString());
        assertTrue(java.startsWith(Path.of(System.getProperty("java.home"))), "never the current process's launcher");
    }
}
