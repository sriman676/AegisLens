package com.aegislens.core;

/** Thrown when a file is empty, truncated or its headers do not make sense. */
public class CorruptFileException extends AnalysisException {

    public CorruptFileException(String message) {
        super(message);
    }

    public CorruptFileException(String message, Throwable cause) {
        super(message, cause);
    }
}
