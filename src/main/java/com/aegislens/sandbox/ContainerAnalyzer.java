package com.aegislens.sandbox;

import com.aegislens.core.AnalysisException;
import com.aegislens.core.Analyzer;
import com.aegislens.core.Finding;

import java.nio.file.Path;
import java.util.List;

/** Runs a sample file in the container sandbox (disabled unless explicitly enabled) and reports its behaviour. */
public class ContainerAnalyzer extends Analyzer<Path> {

    private final ContainerSandbox sandbox;

    public ContainerAnalyzer(ContainerSandbox sandbox) {
        super("container-sandbox");
        this.sandbox = sandbox;
    }

    public ContainerAnalyzer() {
        this(ContainerSandbox.fromEnvironment());
    }

    @Override
    public List<Finding> analyze(Path sample) throws AnalysisException {
        return BehaviourFindings.from(sandbox.run(sample));
    }
}
