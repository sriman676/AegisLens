package com.aegislens.app;

import java.nio.file.Path;

/**
 * Where AegisLens keeps its files: one per-user data folder (default ~/.aegislens) holding the database,
 * aegislens.properties, logs and backups. Built only with Path.resolve, so it works on every operating system.
 */
public final class AppPaths {

    public static final String FOLDER_NAME = ".aegislens";
    public static final String CONFIG_FILE = "aegislens.properties";

    private final Path dataDir;

    public AppPaths(Path dataDir) {
        this.dataDir = dataDir.toAbsolutePath().normalize();
    }

    /** The per-user default: user.home/.aegislens. */
    public static AppPaths defaultPaths() {
        return new AppPaths(Path.of(System.getProperty("user.home"), FOLDER_NAME));
    }

    public Path dataDir() {
        return dataDir;
    }

    public Path configFile() {
        return dataDir.resolve(CONFIG_FILE);
    }

    public Path logsDir() {
        return dataDir.resolve("logs");
    }

    public Path backupsDir() {
        return dataDir.resolve("backups");
    }
}
