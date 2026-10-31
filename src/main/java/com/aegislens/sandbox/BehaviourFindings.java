package com.aegislens.sandbox;

import com.aegislens.core.Finding;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Turns a SandboxReport into Findings (rules SBX-001 to SBX-005, scores: README, Detection rules).
 * Shared by the local and the container sandbox so both report behaviour the same way.
 */
public final class BehaviourFindings {

    private BehaviourFindings() {
    }

    public static List<Finding> from(SandboxReport r) {
        String source = "sandbox-" + r.backend();
        Map<String, String> evidence = new LinkedHashMap<>();
        evidence.put("backend", r.backend());
        evidence.put("exitCode", r.exitCode() == null ? "killed" : r.exitCode().toString());
        evidence.put("durationMs", Long.toString(r.durationMs()));
        if (!r.createdFiles().isEmpty()) {
            evidence.put("createdFiles", String.join(", ", r.createdFiles()));
        }

        List<Finding> findings = new ArrayList<>();
        if (!r.createdFiles().isEmpty()) {
            int score = r.createdFiles().size() >= 3 ? 60 : 45;
            findings.add(new Finding(source, r.subject(), "SBX-001", score,
                    "The program created " + r.createdFiles().size() + " file(s) while running", evidence, null));
        }
        if (r.timedOut()) {
            findings.add(new Finding(source, r.subject(), "SBX-002", 55,
                    "The program did not finish and was killed after the time limit (hang or CPU burn)", evidence, null));
        }
        if (r.outputTruncated()) {
            findings.add(new Finding(source, r.subject(), "SBX-003", 40,
                    "The program produced far more output than the limit allows", evidence, null));
        }
        if (r.exitCode() != null && r.exitCode() != 0) {
            findings.add(new Finding(source, r.subject(), "SBX-004", 25,
                    "The program exited with error code " + r.exitCode(), evidence, null));
        }
        if (r.oomKilled()) {
            findings.add(new Finding(source, r.subject(), "SBX-005", 50,
                    "The program was killed for using more memory than allowed", evidence, null));
        }
        return findings;
    }
}
