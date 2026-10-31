package com.aegislens.ui;

import com.aegislens.sandbox.SandboxReport;

/**
 * Logic of the Sandbox view, kept out of JavaFX so it is unit-tested: a one-line summary of a run and the text that
 * explains the container sandbox's state.
 */
public final class SandboxPresenter {

    private SandboxPresenter() {
    }

    /** "exit 0 after 312 ms · 3 file(s) created" or "stopped: time limit reached after 5003 ms". */
    public static String summary(SandboxReport r) {
        String end = r.timedOut() ? "stopped: time limit reached" : r.oomKilled() ? "stopped: memory limit reached"
                : "exit " + r.exitCode();
        return end + " after " + r.durationMs() + " ms  ·  " + r.createdFiles().size() + " file(s) created"
                + (r.outputTruncated() ? "  ·  output cut at the limit" : "");
    }

    /** What the container button can do right now. */
    public static String containerText(String state) {
        return switch (state) {
            case "ready" -> "Container sandbox: ready. Run unknown samples only inside a disposable VM (README: Security and safety).";
            case "no engine" -> "Container sandbox: enabled, but no Docker or Podman engine answers.";
            default -> "Container sandbox: off. It stays off unless AEGISLENS_ENABLE_REAL_SANDBOX=1 is set, inside a "
                    + "disposable VM with Docker or Podman (README: Security and safety).";
        };
    }
}
