package com.aegislens.db;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

/**
 * Opens the application's database in its data folder the safe way:
 * native-library temp folder inside the data folder, single-instance lock, integrity check with a fresh start
 * if the file is corrupt, and owner-only file permissions where the OS supports POSIX permissions.
 * Call open() before anything else touches SQLite in this process, so the tmpdir setting takes effect.
 */
public final class AppDatabase implements AutoCloseable {

    public static final String DB_FILE = "aegislens.db";
    public static final String TMPDIR_PROPERTY = "org.sqlite.tmpdir";
    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private final Database database;
    private final InstanceLock lock;
    private final String warning;

    private AppDatabase(Database database, InstanceLock lock, String warning) {
        this.database = database;
        this.lock = lock;
        this.warning = warning;
    }

    /**
     * Opens dataDir/aegislens.db. Throws AlreadyRunningException if another AegisLens uses the same folder.
     * The folder's permissions are tightened only if this call created it, so passing a shared folder never locks others out.
     */
    public static AppDatabase open(Path dataDir) throws SQLException, IOException, AlreadyRunningException {
        boolean created = !Files.exists(dataDir);
        Files.createDirectories(dataDir);
        if (created) {
            restrictToOwner(dataDir, "rwx------");
        }
        useTempFolderIn(dataDir);
        InstanceLock lock = InstanceLock.acquire(dataDir);
        try {
            return openLocked(dataDir.resolve(DB_FILE), lock);
        } catch (SQLException | IOException | RuntimeException e) {
            lock.close();
            throw e;
        }
    }

    private static AppDatabase openLocked(Path file, InstanceLock lock) throws SQLException, IOException {
        String warning = null;
        Database db;
        try {
            db = openChecked(file);
        } catch (SQLException corrupt) {
            Path moved = moveAside(file);
            warning = "The database was damaged and has been moved to " + moved.getFileName()
                    + ". A new, empty database was created.";
            db = Database.open(file);
        }
        try {
            restrictToOwner(file, "rw-------");
        } catch (IOException | RuntimeException e) {
            db.close();                     // do not leak the open connections
            throw e;
        }
        return new AppDatabase(db, lock, warning);
    }

    public Database database() {
        return database;
    }

    /** A message for the user if the database had to be replaced at start, otherwise empty. */
    public Optional<String> warning() {
        return Optional.ofNullable(warning);
    }

    /** Points sqlite-jdbc's native-library extraction at dataDir/tmp (works where /tmp is noexec), unless already set. */
    static void useTempFolderIn(Path dataDir) throws IOException {
        if (System.getProperty(TMPDIR_PROPERTY) == null) {
            Path tmp = Files.createDirectories(dataDir.resolve("tmp"));
            System.setProperty(TMPDIR_PROPERTY, tmp.toAbsolutePath().toString());
        }
    }

    /** Opens the file and runs PRAGMA quick_check; any failure means "corrupt". */
    private static Database openChecked(Path file) throws SQLException {
        Database db = Database.open(file);
        try {
            String result = db.locked(c -> {
                try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("PRAGMA quick_check")) {
                    return rs.next() ? rs.getString(1) : "no result";
                }
            });
            if (!"ok".equalsIgnoreCase(result)) {
                throw new SQLException("quick_check failed: " + result);
            }
            return db;
        } catch (SQLException | RuntimeException e) {
            db.close();
            throw e;
        }
    }

    /** Renames the damaged file (and its WAL/SHM side files) to *.corrupt-&lt;UTC time&gt; and returns the new name. */
    private static Path moveAside(Path file) throws IOException {
        String stamp = ZonedDateTime.now(ZoneOffset.UTC).format(STAMP);      // no ':' so it is valid on Windows too
        Path moved = file.resolveSibling(file.getFileName() + ".corrupt-" + stamp);
        Files.move(file, moved, StandardCopyOption.REPLACE_EXISTING);
        for (String side : new String[] {"-wal", "-shm"}) {
            Path sideFile = file.resolveSibling(file.getFileName() + side);
            if (Files.exists(sideFile)) {
                Files.move(sideFile, moved.resolveSibling(moved.getFileName() + side), StandardCopyOption.REPLACE_EXISTING);
            }
        }
        return moved;
    }

    /** Owner-only access on Linux/macOS. Windows has no POSIX permissions: the user profile's NTFS ACL protects the folder there. */
    private static void restrictToOwner(Path path, String permissions) throws IOException {
        if (!Files.exists(path)) {
            return;
        }
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(permissions));
        } catch (UnsupportedOperationException notPosix) {
            // Windows: nothing to do here (see Javadoc)
        }
    }

    /** Closes the database, then releases the instance lock. */
    @Override
    public void close() throws SQLException, IOException {
        try {
            database.close();
        } finally {
            lock.close();
        }
    }
}
