package com.aegislens.sandbox.demo;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Entry point of the harmless demo programs. It runs in a CHILD JVM started by LocalSandbox, never in the app itself.
 * Every behaviour here is a safe imitation: it only writes to its own working directory and prints text.
 */
public final class DemoMain {

    private DemoMain() {
    }

    public static void main(String[] args) throws Exception {
        String which = args.length > 0 ? args[0] : "hello";
        switch (which) {
            case "hello" -> System.out.println("hello from the sandbox");
            case "dropper" -> {
                for (int i = 1; i <= 3; i++) {
                    Files.writeString(Path.of("dropped_" + i + ".txt"), "harmless demo file " + i);
                }
                System.out.println("dropped 3 files");
            }
            case "burner" -> {
                long x = 0;
                while (true) {
                    x++;
                    if (x == Long.MIN_VALUE) {
                        System.out.println(x);   // never happens; stops the loop being optimised away
                    }
                }
            }
            case "chatty" -> {
                String line = "x".repeat(100);
                for (int i = 0; i < 100_000; i++) {
                    System.out.println(line);
                }
            }
            case "crash" -> throw new IllegalStateException("simulated crash");
            case "env" -> System.out.println("pathVisible=" + (System.getenv("PATH") != null)
                    + " apiKeyVisible=" + (System.getenv("CLAUDE_API_KEY") != null));
            default -> {
                System.err.println("unknown demo: " + which);
                System.exit(2);
            }
        }
    }
}
