package com.aegislens.db;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Many threads mixing read(), locked() and nested transaction() (which also reads inside) must never deadlock
 *. ThreadMXBean asks the JVM whether any threads wait for each other in a cycle.
 */
class DeadlockTest {

    private static final int THREADS = 8;
    private static final int ROUNDS = 60;

    @TempDir
    Path dir;

    @Test
    void mixedLockUseNeverDeadlocks() throws Exception {
        try (Database db = Database.open(dir.resolve("d.db"))) {
            SettingRepository settings = new SettingRepository(db);
            AuditLogRepository audit = new AuditLogRepository(db);
            List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());
            List<Thread> threads = new ArrayList<>();
            for (int t = 0; t < THREADS; t++) {
                int id = t;
                Thread th = new Thread(() -> work(db, settings, audit, id, errors), "mixer-" + t);
                threads.add(th);
                th.start();
            }
            for (Thread th : threads) {
                th.join(60_000);
            }
            ThreadMXBean mx = ManagementFactory.getThreadMXBean();
            assertNull(mx.findDeadlockedThreads(), "deadlocked threads found");
            assertTrue(threads.stream().noneMatch(Thread::isAlive), "every thread finished");
            assertTrue(errors.isEmpty(), "no thread may fail: " + errors);
            assertEquals(THREADS * ROUNDS, audit.count());
        }
    }

    private static void work(Database db, SettingRepository settings, AuditLogRepository audit, int id, List<Throwable> errors) {
        try {
            for (int i = 0; i < ROUNDS; i++) {
                switch (i % 3) {
                    case 0 -> settings.put("t" + id, String.valueOf(i));
                    case 1 -> settings.all();
                    default -> db.transaction(c -> {
                        db.transaction(inner -> settings.get("t" + id));      // nested + read while holding the write lock
                        return null;
                    });
                }
                audit.append("t" + id, "ROUND", null);
            }
        } catch (Throwable e) {
            errors.add(e);
        }
    }
}
