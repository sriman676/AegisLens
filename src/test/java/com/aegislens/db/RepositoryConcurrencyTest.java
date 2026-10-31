package com.aegislens.db;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Several repositories used from several threads at once on a real file database (WAL, writer + reader). */
class RepositoryConcurrencyTest {

    private static final int THREADS = 6;
    private static final int ROUNDS = 40;

    @TempDir
    Path dir;

    @Test
    void mixedReadsAndWritesFromManyThreads() throws Exception {
        try (Database db = Database.open(dir.resolve("c.db"))) {
            IocRepository iocs = new IocRepository(db);
            AuditLogRepository audit = new AuditLogRepository(db);
            SettingRepository settings = new SettingRepository(db);
            List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());
            List<Thread> threads = new ArrayList<>();
            for (int t = 0; t < THREADS; t++) {
                int id = t;
                Thread th = new Thread(() -> {
                    try {
                        for (int i = 0; i < ROUNDS; i++) {
                            iocs.addAll("IP", List.of("10.1." + id + "." + i, "10.0.0.0"), "t" + id);
                            audit.append("t" + id, "ROUND", String.valueOf(i));
                            settings.put("thread." + id, String.valueOf(i));
                            iocs.values("IP");
                            audit.recent(5);
                        }
                    } catch (Throwable e) {
                        errors.add(e);
                    }
                }, "worker-" + t);
                threads.add(th);
                th.start();
            }
            for (Thread th : threads) {
                th.join(60_000);
            }
            assertTrue(errors.isEmpty(), "no thread may fail: " + errors);
            assertEquals(THREADS * ROUNDS + 1, iocs.values("IP").size(), "one shared duplicate, stored once");
            assertEquals(THREADS * ROUNDS, audit.count());
            assertEquals(String.valueOf(ROUNDS - 1), settings.get("thread.0").orElseThrow());
        }
    }
}
