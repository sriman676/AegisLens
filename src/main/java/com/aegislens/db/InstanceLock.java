package com.aegislens.db;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Single-instance guard: an operating-system file lock on aegislens.lock in the data folder.
 * The OS releases the lock automatically if the process dies, so a crash never leaves a stale lock behind.
 */
public final class InstanceLock implements AutoCloseable {

    public static final String FILE_NAME = "aegislens.lock";

    private final FileChannel channel;
    private final FileLock lock;

    private InstanceLock(FileChannel channel, FileLock lock) {
        this.channel = channel;
        this.lock = lock;
    }

    /** Takes the lock or throws AlreadyRunningException if another instance holds it. */
    public static InstanceLock acquire(Path dataDir) throws IOException, AlreadyRunningException {
        Files.createDirectories(dataDir);
        Path file = dataDir.resolve(FILE_NAME);
        FileChannel channel = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock lock = null;
        try {
            lock = channel.tryLock();
        } catch (OverlappingFileLockException e) {
            lock = null;                       // this JVM already holds it (a second open in the same process)
        } finally {
            if (lock == null) {
                channel.close();
            }
        }
        if (lock == null) {
            throw new AlreadyRunningException("AegisLens is already running (lock file: " + file + ")");
        }
        return new InstanceLock(channel, lock);
    }

    @Override
    public void close() throws IOException {
        try {
            lock.release();
        } finally {
            channel.close();
        }
    }
}
