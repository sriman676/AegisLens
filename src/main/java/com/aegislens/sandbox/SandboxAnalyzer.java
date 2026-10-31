package com.aegislens.sandbox;

import com.aegislens.core.AnalysisException;
import com.aegislens.core.Analyzer;
import com.aegislens.core.Finding;

import java.util.List;

/** Runs a DemoProgram in the local sandbox and reports what it did (an Analyzer<DemoProgram>). */
public class SandboxAnalyzer extends Analyzer<DemoProgram> {

    private final LocalSandbox sandbox;

    public SandboxAnalyzer(LocalSandbox sandbox) {
        super("local-sandbox");
        this.sandbox = sandbox;
    }

    public SandboxAnalyzer() {
        this(new LocalSandbox());
    }

    @Override
    public List<Finding> analyze(DemoProgram demo) throws AnalysisException {
        return BehaviourFindings.from(sandbox.run(demo));
    }
}
