package com.aegislens.sandbox;

import java.util.List;

/**
 * What we observed while something ran in a sandbox.
 *
 * @param backend         "local-demo" or "container"
 * @param subject         demo id, or the sample file name
 * @param exitCode        process exit code, or null if it was killed after a timeout
 * @param timedOut        true if the time limit was hit and the run was killed
 * @param oomKilled       true if the container ran out of memory
 * @param durationMs      how long it ran
 * @param output          captured stdout and stderr (capped). Display it in a plain TextArea only
 * @param outputTruncated true if more output was produced than we kept
 * @param createdFiles    files the run created (relative paths, sorted)
 */
public record SandboxReport(String backend, String subject, Integer exitCode, boolean timedOut, boolean oomKilled,
                            long durationMs, String output, boolean outputTruncated, List<String> createdFiles) {

    public SandboxReport {
        createdFiles = List.copyOf(createdFiles);
    }
}
