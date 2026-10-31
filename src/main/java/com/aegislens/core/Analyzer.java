package com.aegislens.core;

import java.util.List;

/**
 * Parent of every analyzer. T is the kind of input (a Path for files, a String for URLs).
 */
public abstract class Analyzer<T> {

    protected final String name;

    protected Analyzer(String name) {
        this.name = name;
    }

    public String name() {
        return name;
    }

    /** Looks at the input and returns zero or more findings. */
    public abstract List<Finding> analyze(T input) throws AnalysisException;
}
