package com.aegislens.app;

import com.aegislens.core.AlertBus;
import com.aegislens.core.Finding;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.ScanSessionRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class PersisterThreadTest {

    private static final int PRODUCERS = 3;
    private static final int PER_PRODUCER = 100;

    @TempDir
    Path dir;

    @Test
    void threeProducersEverythingIsSavedInSessionsPerModule() throws Exception {
        try (Database db = Database.open(dir.resolve("p.db"))) {
            AlertBus bus = new AlertBus(50);                   // small, so producers really wait for the consumer
            PersisterThread persister = persister(db, bus, AllowList.parse(""));
            AtomicInteger heard = new AtomicInteger();
            persister.addListener(f -> heard.incrementAndGet());
            persister.addListener(f -> {
                throw new IllegalStateException("a broken listener must not stop saving");
            });
            persister.start();

            String[] rules = {"NET-001", "MAL-002", "WEB-002"};
            List<Thread> producers = new ArrayList<>();
            List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());
            for (int p = 0; p < PRODUCERS; p++) {
                int id = p;
                Thread t = new Thread(() -> {
                    try {
                        for (int i = 0; i < PER_PRODUCER; i++) {
                            bus.publish(new Finding("t", "203.0.113." + id + "-" + i, rules[id], 60, "x"));
                        }
                    } catch (Throwable e) {
                        errors.add(e);
                    }
                });
                producers.add(t);
                t.start();
            }
            for (Thread t : producers) {
                t.join(30_000);
            }
            bus.close();
            persister.join(30_000);

            assertTrue(errors.isEmpty(), errors.toString());
            assertEquals(Thread.State.TERMINATED, persister.getState(), "take() returned null, so the thread ended");
            assertEquals(PRODUCERS * PER_PRODUCER, persister.savedCount());
            assertEquals(PRODUCERS * PER_PRODUCER, new FindingRepository(db).count());
            assertEquals(PRODUCERS * PER_PRODUCER, heard.get());
            assertEquals(Set.of("INTRUSION", "MALWARE", "WEB"), modulesWithSessions(db));
        }
    }

    @Test
    void allowListedAndDuplicateFindingsAreDropped() throws Exception {
        try (Database db = Database.inMemory()) {
            AlertBus bus = new AlertBus();
            PersisterThread persister = persister(db, bus, AllowList.parse("10.0.0.0/8"));
            persister.start();
            bus.publish(new Finding("ssh", "10.1.2.3", "NET-001", 70, "trusted"));
            bus.publish(new Finding("ssh", "203.0.113.9", "NET-001", 70, "first"));
            bus.publish(new Finding("ssh", "203.0.113.9", "NET-001", 70, "repeat"));
            bus.close();
            persister.join(10_000);
            assertEquals(1, persister.savedCount());
            assertEquals(1, persister.allowListedCount());
            assertEquals(1, persister.dedupedCount());
        }
    }

    @Test
    void moduleComesFromTheRulePrefix() {
        assertEquals("MALWARE", PersisterThread.moduleFor("MAL-004"));
        assertEquals("SANDBOX", PersisterThread.moduleFor("SBX-001"));
        assertEquals("HOST", PersisterThread.moduleFor("HOST-001"));
        assertEquals("INTRUSION", PersisterThread.moduleFor("ZZZ"));
        assertEquals(Thread.NORM_PRIORITY + 1, new PersisterThread(new AlertBus(), null, null, null, null).getPriority());
    }

    private static PersisterThread persister(Database db, AlertBus bus, AllowList allow) {
        return new PersisterThread(bus, new FindingRepository(db), new ScanSessionRepository(db),
                new AlertDeduper(Duration.ofMinutes(10)), allow);
    }

    private static Set<String> modulesWithSessions(Database db) throws Exception {
        return db.read(c -> {
            Set<String> modules = new HashSet<>();
            try (var ps = c.prepareStatement("SELECT module, status FROM scan_session"); var rs = ps.executeQuery()) {
                while (rs.next()) {
                    assertEquals("DONE", rs.getString(2), "sessions are closed when the persister ends");
                    modules.add(rs.getString(1));
                }
            }
            return modules;
        });
    }
}
