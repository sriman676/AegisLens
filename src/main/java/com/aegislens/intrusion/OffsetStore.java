package com.aegislens.intrusion;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Where tailers remember how far they read each file, so a restart neither re-alerts nor loses lines.
 * The app implements it on top of the log_offset table; intrusion never touches the database itself.
 * Implementations must not throw: a failed save is logged, and the worst case is re-reading a few lines.
 */
public interface OffsetStore {

    /** A saved position and the fingerprint of the file it belongs to. */
    record Saved(long offset, String fingerprint) {
    }

    Optional<Saved> load(Path file);

    void save(Path file, long offset, String fingerprint);

    /** An in-memory store (tests, and replay runs that must not touch the database). */
    static OffsetStore inMemory() {
        java.util.Map<Path, Saved> map = new java.util.concurrent.ConcurrentHashMap<>();
        return new OffsetStore() {
            @Override
            public Optional<Saved> load(Path file) {
                return Optional.ofNullable(map.get(file.toAbsolutePath().normalize()));
            }

            @Override
            public void save(Path file, long offset, String fingerprint) {
                map.put(file.toAbsolutePath().normalize(), new Saved(offset, fingerprint));
            }
        };
    }
}
