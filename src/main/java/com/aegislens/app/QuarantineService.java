package com.aegislens.app;

import com.aegislens.db.AuditLogRepository;
import com.aegislens.db.QuarantineEntry;
import com.aegislens.db.QuarantineRepository;
import com.aegislens.malware.HashUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.UUID;

/**
 * Reversible quarantine, only on the analyst's explicit request. The file's bytes are XOR-scrambled with a random key
 * and moved into the vault (data folder/quarantine/&lt;uuid&gt;.aqv, starting with "AEGISQ1" and the 32-byte key), so the
 * copy can neither run nor be opened by accident, and antivirus does not keep re-detecting it. Restore unscrambles it,
 * checks the SHA-256 against the record, and never overwrites an existing file. Every step is written to the audit log.
 * This is not encryption for secrecy: the goal is "cannot be executed by mistake".
 */
public final class QuarantineService {

    public static final byte[] MAGIC = "AEGISQ1".getBytes(StandardCharsets.US_ASCII);
    public static final int KEY_BYTES = 32;
    public static final String SUFFIX = ".aqv";
    private static final int BUFFER = 64 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path vault;
    private final QuarantineRepository records;
    private final AuditLogRepository audit;

    public QuarantineService(Path vault, QuarantineRepository records, AuditLogRepository audit) {
        this.vault = vault;
        this.records = records;
        this.audit = audit;
    }

    public Path vault() {
        return vault;
    }

    /** Moves the file into the vault (scrambled) and returns the quarantine id. */
    public long quarantine(Path file, String reason) throws IOException, SQLException {
        if (!Files.isRegularFile(file)) {
            throw new IOException("Not a regular file: " + file);
        }
        Files.createDirectories(vault);
        Path original = file.toAbsolutePath().normalize();
        String sha256 = HashUtil.sha256(original);
        Path target = vault.resolve(UUID.randomUUID() + SUFFIX);
        byte[] key = new byte[KEY_BYTES];
        RANDOM.nextBytes(key);
        try (InputStream in = Files.newInputStream(original); OutputStream out = Files.newOutputStream(target)) {
            out.write(MAGIC);
            out.write(key);
            xorCopy(in, out, key);
        }
        long id;
        try {
            id = records.add(original.toString(), target.toString(), sha256, reason);
            Files.delete(original);                           // only after the vault copy and the record exist
        } catch (IOException | SQLException e) {
            Files.deleteIfExists(target);                     // undo: the original stays where it was
            throw e;
        }
        audit.append("analyst", "QUARANTINE", original + " (sha256 " + sha256 + ")");
        return id;
    }

    /** Puts the file back where it was (with a ".restored" name if that place is taken) and returns the new path. */
    public Path restore(long id) throws IOException, SQLException {
        QuarantineEntry e = records.find(id).orElseThrow(() -> new IOException("No quarantine record " + id));
        if (e.restored()) {
            throw new IOException("Already restored: " + e.originalPath());
        }
        Path source = Path.of(e.vaultPath());
        Path target = freeName(Path.of(e.originalPath()));
        Files.createDirectories(target.toAbsolutePath().getParent());
        Path temp = target.resolveSibling(target.getFileName() + ".restoring");
        try (InputStream in = Files.newInputStream(source); OutputStream out = Files.newOutputStream(temp)) {
            byte[] magic = in.readNBytes(MAGIC.length);
            byte[] key = in.readNBytes(KEY_BYTES);
            if (!Arrays.equals(magic, MAGIC) || key.length != KEY_BYTES) {
                throw new IOException("Not an AegisLens vault file: " + source);
            }
            xorCopy(in, out, key);
        }
        if (!HashUtil.sha256(temp).equals(e.sha256())) {
            Files.delete(temp);
            throw new IOException("Vault file is damaged (SHA-256 does not match); nothing was restored");
        }
        Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE);
        Files.delete(source);
        records.markRestored(id);
        audit.append("analyst", "RESTORE", target.toString());
        return target;
    }

    /** Copies in to out, XOR-ing every byte with the key (applying it twice gives the original back). */
    static void xorCopy(InputStream in, OutputStream out, byte[] key) throws IOException {
        byte[] buf = new byte[BUFFER];
        long position = 0;
        int n;
        while ((n = in.read(buf)) > 0) {
            for (int i = 0; i < n; i++) {
                buf[i] ^= key[(int) ((position + i) % key.length)];
            }
            out.write(buf, 0, n);
            position += n;
        }
    }

    /** The path itself if free, else name.restored-1, name.restored-2, ... */
    private static Path freeName(Path p) {
        Path candidate = p;
        for (int i = 1; Files.exists(candidate); i++) {
            candidate = p.resolveSibling(p.getFileName() + ".restored-" + i);
        }
        return candidate;
    }
}
