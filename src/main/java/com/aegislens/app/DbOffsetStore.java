package com.aegislens.app;

import com.aegislens.db.LogOffset;
import com.aegislens.db.LogOffsetRepository;
import com.aegislens.intrusion.OffsetStore;

import java.nio.file.Path;
import java.sql.SQLException;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Tailer offsets kept in the log_offset table, so a restart of AegisLens continues where it stopped.
 * Database errors are logged, never thrown: the worst case is reading a few lines again (the deduper absorbs repeats).
 */
public final class DbOffsetStore implements OffsetStore {

    private static final Logger LOG = Logger.getLogger(DbOffsetStore.class.getName());

    private final LogOffsetRepository repo;

    public DbOffsetStore(LogOffsetRepository repo) {
        this.repo = repo;
    }

    @Override
    public Optional<Saved> load(Path file) {
        try {
            Optional<LogOffset> o = repo.get(file);
            return o.map(x -> new Saved(x.offset(), x.fingerprint()));
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Could not read the saved offset of " + file, e);
            return Optional.empty();
        }
    }

    @Override
    public void save(Path file, long offset, String fingerprint) {
        try {
            repo.put(file, offset, fingerprint);
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Could not save the offset of " + file, e);
        }
    }
}
