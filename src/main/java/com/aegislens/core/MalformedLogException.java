package com.aegislens.core;

/** Thrown when one log line cannot be parsed. Callers log it, count it and skip the line. */
public class MalformedLogException extends AnalysisException {

    public MalformedLogException(String message) {
        super(message);
    }

    public MalformedLogException(String message, Throwable cause) {
        super(message, cause);
    }
}
