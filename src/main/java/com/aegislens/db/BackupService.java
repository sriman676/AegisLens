package com.aegislens.db;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Online backups with SQLite's "VACUUM INTO": the copy is written under a temporary name and renamed
 * only after it succeeded, so a power cut never leaves a half-written file with a real backup name.
 * Keeps the newest KEEP backups., java.nio.file (platform independent paths), ArrayList.
 */
public final class BackupService {

    public static final int KEEP = 7;
    private static final String PREFIX = "backup-";
    private static final String SUFFIX = ".db";

    private final Database db;

    public BackupService(Database db) {
        this.db = db;
    }

    /** Writes backup-&lt;date&gt;.db into dir (replacing one from the same day) and prunes old backups. Returns the file. */
    public Path backup(Path dir, LocalDate date) throws SQLException, IOException {
        Files.createDirectories(dir);
        Path target = dir.resolve(PREFIX + date + SUFFIX);
        Path temp = dir.resolve(PREFIX + date + SUFFIX + ".tmp");
        Files.deleteIfExists(temp);                       // VACUUM INTO needs a new or empty file
        db.locked(c -> {
            try (PreparedStatement ps = c.prepareStatement("VACUUM INTO ?")) {
                ps.setString(1, temp.toAbsolutePath().toString());
                ps.execute();
            }
            return null;
        });
        Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
        prune(dir);
        return target;
    }

    /** The backups in dir, newest first (the ISO date in the name sorts correctly as text). */
    public static List<Path> list(Path dir) throws IOException {
        List<Path> backups = new ArrayList<>();
        if (!Files.isDirectory(dir)) {
            return backups;
        }
        try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, PREFIX + "*" + SUFFIX)) {
            for (Path p : files) {
                backups.add(p);
            }
        }
        backups.sort(Comparator.comparing((Path p) -> p.getFileName().toString()).reversed());
        return backups;
    }

    private static void prune(Path dir) throws IOException {
        List<Path> backups = list(dir);
        for (int i = KEEP; i < backups.size(); i++) {
            Files.deleteIfExists(backups.get(i));
        }
    }
}
