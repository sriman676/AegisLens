package com.aegislens.app;

import com.aegislens.core.AlertBus;
import com.aegislens.core.Finding;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.ScanSessionRepository;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The single consumer of the AlertBus: waits for a finding, grabs up to BATCH queued ones, drops allow-listed and
 * duplicate findings, puts each into a scan session for its module, saves the batch in one transaction, then tells
 * the listeners (the UI). Ends when the bus is closed and empty (take() returns null).
 */
public final class PersisterThread extends Thread {

    public static final int BATCH = 200;
    public static final String THREAD_NAME = "aegislens-persister";

    private static final Logger LOG = Logger.getLogger(PersisterThread.class.getName());
    private static final Map<String, String> MODULE_BY_PREFIX = new HashMap<>();

    static {
        MODULE_BY_PREFIX.put("MAL", "MALWARE");
        MODULE_BY_PREFIX.put("NET", "INTRUSION");
        MODULE_BY_PREFIX.put("WEB", "WEB");
        MODULE_BY_PREFIX.put("SBX", "SANDBOX");
        MODULE_BY_PREFIX.put("HOST", "HOST");
    }

    private final AlertBus bus;
    private final FindingRepository findings;
    private final ScanSessionRepository sessions;
    private final AlertDeduper deduper;
    private volatile AllowList allowList;
    private final Map<String, Long> sessionByModule = new HashMap<>();      // used only by this thread
    private final List<Consumer<Finding>> listeners = new CopyOnWriteArrayList<>();
    private final AtomicLong saved = new AtomicLong();
    private final AtomicLong allowListed = new AtomicLong();
    private final AtomicLong failed = new AtomicLong();

    public PersisterThread(AlertBus bus, FindingRepository findings, ScanSessionRepository sessions,
                           AlertDeduper deduper, AllowList allowList) {
        super(THREAD_NAME);
        this.bus = bus;
        this.findings = findings;
        this.sessions = sessions;
        this.deduper = deduper;
        this.allowList = allowList;
        setPriority(NORM_PRIORITY + 1);        // saving alerts matters more than background work, less than the UI thread
    }

    /** Module for a rule id such as NET-001 (unknown prefixes count as INTRUSION). */
    public static String moduleFor(String ruleId) {
        int dash = ruleId.indexOf('-');
        String prefix = dash > 0 ? ruleId.substring(0, dash) : ruleId;
        return MODULE_BY_PREFIX.getOrDefault(prefix, "INTRUSION");
    }

    /** Called (on this thread) for every saved finding. Listeners must be quick; the UI hands work to Platform.runLater. */
    public void addListener(Consumer<Finding> listener) {
        listeners.add(listener);
    }

    /** Swaps in a new allow-list (for example after the user edits it in Settings). */
    public void setAllowList(AllowList allowList) {
        this.allowList = allowList;
    }

    @Override
    public void run() {
        try {
            Finding first;
            while ((first = bus.take()) != null) {
                List<Finding> batch = new ArrayList<>();
                batch.add(first);
                bus.drainTo(batch, BATCH - 1);
                process(batch);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();       // asked to stop early: keep the flag and leave
        } finally {
            finishSessions();
        }
    }

    private void process(List<Finding> batch) {
        List<Finding> toSave = new ArrayList<>();
        for (Finding f : batch) {
            if (allowList.isTrusted(f)) {
                allowListed.incrementAndGet();
                continue;
            }
            Optional<Finding> forwarded = deduper.offer(f);
            forwarded.ifPresent(toSave::add);
        }
        if (toSave.isEmpty()) {
            return;
        }
        try {
            for (Finding f : toSave) {
                f.setSessionId(sessionFor(moduleFor(f.ruleId())));
            }
            findings.saveAll(toSave);
            saved.addAndGet(toSave.size());
        } catch (SQLException e) {
            failed.addAndGet(toSave.size());
            LOG.log(Level.SEVERE, "Could not save " + toSave.size() + " findings", e);
            return;
        }
        notifyListeners(toSave);
    }

    private long sessionFor(String module) throws SQLException {
        Long id = sessionByModule.get(module);
        if (id == null) {
            id = sessions.begin(module, "live pipeline");
            sessionByModule.put(module, id);
        }
        return id;
    }

    private void notifyListeners(List<Finding> savedFindings) {
        for (Finding f : savedFindings) {
            for (Consumer<Finding> listener : listeners) {
                try {
                    listener.accept(f);
                } catch (RuntimeException e) {
                    LOG.log(Level.WARNING, "A finding listener failed", e);   // one bad listener must not stop saving
                }
            }
        }
    }

    private void finishSessions() {
        for (long id : sessionByModule.values()) {
            try {
                sessions.finish(id, true);
            } catch (SQLException e) {
                LOG.log(Level.WARNING, "Could not close scan session " + id, e);
            }
        }
    }

    public long savedCount() {
        return saved.get();
    }

    public long allowListedCount() {
        return allowListed.get();
    }

    public long dedupedCount() {
        return deduper.droppedTotal();
    }

    public long failedCount() {
        return failed.get();
    }
}
