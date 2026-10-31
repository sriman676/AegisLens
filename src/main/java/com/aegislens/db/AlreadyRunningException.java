package com.aegislens.db;

/**
 * Thrown when another AegisLens already holds the data folder's lock, so a second copy does not tail the same logs
 * or write the same database twice.
 */
public class AlreadyRunningException extends Exception {

    public AlreadyRunningException(String message) {
        super(message);
    }
}
