package com.aegislens.app;

import com.aegislens.ai.ExplanationService;
import com.aegislens.core.AlertBus;
import com.aegislens.core.Finding;
import com.aegislens.core.Severity;
import com.aegislens.db.AlreadyRunningException;
import com.aegislens.db.AppDatabase;
import com.aegislens.db.BackupService;
import com.aegislens.db.AiExplanationRepository;
import com.aegislens.db.AuditLogRepository;
import com.aegislens.db.Database;
import com.aegislens.db.FileReport;
import com.aegislens.db.FeedStateRepository;
import com.aegislens.db.FileReportRepository;
import com.aegislens.db.QuarantineEntry;
import com.aegislens.db.QuarantineRepository;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.IocRepository;
import com.aegislens.db.LogOffsetRepository;
import com.aegislens.db.RetentionJob;
import com.aegislens.db.RuleRepository;
import com.aegislens.db.ScanSessionRepository;
import com.aegislens.db.SettingRepository;
import com.aegislens.db.VtCacheRepository;
import com.aegislens.db.VtResult;
import com.aegislens.intel.FeedCatalog;
import com.aegislens.intel.FeedDefinition;
import com.aegislens.intel.FeedUpdater;
import com.aegislens.sandbox.BehaviourFindings;
import com.aegislens.sandbox.ContainerSandbox;
import com.aegislens.sandbox.DemoProgram;
import com.aegislens.sandbox.LocalSandbox;
import com.aegislens.sandbox.SandboxReport;
import com.aegislens.util.InjectionPatterns;
import com.aegislens.web.HeaderChecker;
import com.aegislens.web.HtmlAnalyzer;
import com.aegislens.web.LookalikeChecker;
import com.aegislens.web.UrlAnalyzer;
import com.aegislens.intel.VirusTotalClient;
import com.aegislens.intrusion.DetectionEngine;
import com.aegislens.intrusion.HostDetectionEngine;
import com.aegislens.intrusion.HostNetworkDetector;
import com.aegislens.intrusion.LogEvent;
import com.aegislens.intrusion.LogSource;
import com.aegislens.intrusion.LogType;
import com.aegislens.intrusion.MonitorManager;
import com.aegislens.intrusion.SysmonEvent;
import com.aegislens.intrusion.SysmonXmlSource;
import com.aegislens.intrusion.Thresholds;
import com.aegislens.intrusion.WindowsEventXmlSource;
import com.aegislens.malware.FileScanner;
import com.aegislens.malware.FolderWatcher;
import com.aegislens.malware.ScanResult;
import com.aegislens.net.ConnectivityMonitor;
import com.aegislens.net.HttpClientFactory;
import com.aegislens.net.NetworkSettings;
import com.aegislens.net.RetryPolicy;
import com.aegislens.util.CidrSet;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneId;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Wires the application together: database, AlertBus, PersisterThread, live log monitors, a thread pool for scans, the AI
 * ExplanationService and a daily maintenance job (retention + backup). The UI (and later the headless mode)
 * talks only to this class. Shutdown order: stop monitors and scans, stop maintenance, close the bus, wait for the persister,
 * close the database.,
 * ExecutorService and thread life cycle.
 */
public final class ScanCoordinator implements AutoCloseable {

    public static final Duration MAINTENANCE_PERIOD = Duration.ofDays(1);
    public static final Duration FIRST_MAINTENANCE_DELAY = Duration.ofMinutes(10);
    public static final Duration SHUTDOWN_WAIT = Duration.ofSeconds(10);
    public static final String THREAD_PREFIX = "aegislens-";
    public static final String QUARANTINE_FOLDER = "quarantine";
    /** Comma-separated folders whose new files are scanned automatically (off when empty). */
    public static final String SCAN_FOLDERS = "monitor.scan.folders";
    /** A folder where Sysmon exports (*.xml) are dropped; each new file is replayed once. Off when empty. */
    public static final String SYSMON_FOLDER = "monitor.sysmon.folder";
    /** Settings key prefix: the newest Sysmon event time already read from the watched folder, per computer. */
    static final String SYSMON_SEEN = "sysmon.seen.";
    public static final Duration FIRST_FEED_CHECK = Duration.ofMinutes(1);
    public static final Duration FEED_CHECK_PERIOD = Duration.ofHours(1);
    /** Environment variable holding the webhook URL (a secret). */
    public static final String WEBHOOK_ENV = "AEGISLENS_WEBHOOK_URL";

    private static final Logger LOG = Logger.getLogger(ScanCoordinator.class.getName());

    private final AppDatabase app;                 // null when a test passes its own Database
    private final Database db;
    private final AppConfig config;
    private final SettingRepository settings;
    private final AlertBus bus;
    private final PersisterThread persister;
    private final ExecutorService scanPool;
    private final ScheduledExecutorService maintenance;
    private final ExplanationService explanations;
    private final HttpClientFactory http;
    private final ConnectivityMonitor connectivity;
    private final WebhookNotifier webhook;
    private final FeedUpdater feeds;
    private final ScheduledExecutorService feedScheduler;
    private final VirusTotalClient virusTotal;
    private final ZoneId serverZone;
    private final DetectionEngine engine;
    private final MonitorManager monitors;
    private final LiveRules liveRules = new LiveRules();
    private final List<Runnable> intelListeners = new CopyOnWriteArrayList<>();
    private LookalikeChecker lookalikes;                 // loaded on the first URL check
    private final FileScanner scanner;
    private final QuarantineService quarantine;
    private FolderWatcher folderWatcher;
    private FolderWatcher sysmonWatcher;
    private boolean started;
    private boolean shutDown;

    /** Opens the database in the configured data folder. Throws AlreadyRunningException if another AegisLens uses it. */
    public ScanCoordinator(AppConfig config) throws SQLException, IOException, AlreadyRunningException {
        this(AppDatabase.open(config.paths().dataDir()), config);
    }

    /** Uses a database the caller owns (and closes). Used by tests. */
    public ScanCoordinator(Database db, AppConfig config) {
        this(null, db, config);
    }

    private ScanCoordinator(AppDatabase app, AppConfig config) {
        this(app, app.database(), config);
    }

    private ScanCoordinator(AppDatabase app, Database db, AppConfig config) {
        this.app = app;
        this.db = db;
        this.config = config;
        this.settings = new SettingRepository(db);
        this.bus = new AlertBus(config.getInt(AppConfig.BUS_CAPACITY, AppConfig.DEFAULT_BUS_CAPACITY));
        AlertDeduper deduper = new AlertDeduper(config.getMinutes(AppConfig.DEDUPE_COOLDOWN_MINUTES, AppConfig.DEFAULT_COOLDOWN_MINUTES));
        this.persister = new PersisterThread(bus, new FindingRepository(db), new ScanSessionRepository(db), deduper, loadAllowList());
        int threads = Math.max(1, config.getInt(AppConfig.SCAN_THREADS, AppConfig.DEFAULT_SCAN_THREADS));
        this.scanPool = Executors.newFixedThreadPool(threads, named("scan", Thread.NORM_PRIORITY));
        this.maintenance = Executors.newSingleThreadScheduledExecutor(named("maintenance", Thread.MIN_PRIORITY));
        this.http = new HttpClientFactory(NetworkSettings.from(this::settingOrNull));
        this.explanations = ExplanationService.configured(k -> config.get(k, null), System::getenv, http, RetryPolicy.standard());
        this.explanations.setCache(new DbExplanationCache(new AiExplanationRepository(db)));
        List<URI> cloud = explanations.cloudHosts();
        this.connectivity = cloud.isEmpty() ? null : new ConnectivityMonitor(http.client(), cloud, Clock.systemUTC());
        if (connectivity != null) {
            explanations.setOnline(() -> connectivity.current().online());
        }
        this.webhook = buildWebhook();
        this.feeds = new FeedUpdater(loadFeeds(), http.client(), RetryPolicy.standard(), new IocRepository(db),
                new FeedStateRepository(db), System::getenv, Clock.systemUTC());
        this.feedScheduler = Executors.newSingleThreadScheduledExecutor(named("feeds", Thread.MIN_PRIORITY));
        this.virusTotal = VirusTotalClient.standard(System.getenv("VT_API_KEY"), http.client(), new VtCacheRepository(db));
        this.serverZone = IntrusionSetup.zone(config);
        this.engine = buildEngine();
        this.monitors = new MonitorManager(IntrusionSetup.monitorConfig(config), engine, bus::publish,
                new DbOffsetStore(new LogOffsetRepository(db)), Clock.systemUTC());
        loadRules();
        this.scanner = new FileScanner(this::isKnownBadHash, threads, liveRules);
        this.quarantine = new QuarantineService(config.paths().dataDir().resolve(QUARANTINE_FOLDER),
                new QuarantineRepository(db), new AuditLogRepository(db));
    }

    /** Detectors with thresholds from the rule table and IOC lists from the database (defaults if the DB read fails). */
    private DetectionEngine buildEngine() {
        try {
            CidrSet[] intel = IntrusionSetup.threatIntel(new IocRepository(db));
            return new DetectionEngine(IntrusionSetup.thresholds(new RuleRepository(db), config), intel[0], intel[1]);
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Could not read rules or IOCs; using default thresholds", e);
            return new DetectionEngine(Thresholds.defaults(serverZone), new CidrSet(), new CidrSet());
        }
    }

    /**
     * Replays a whole log file through the detectors on the scan pool; findings go through the normal pipeline
     * (allow-list, dedupe, database, listeners). Windows exports are XML files, the rest are line formats.
     */
    public Future<DetectionEngine.ReplayResult> replayLog(Path file, LogType type) {
        return scanPool.submit(() -> {
            if (type == LogType.SYSMON_XML) {
                return replaySysmon(file, false);
            }
            if (type == LogType.WINDOWS_XML) {
                long count = 0;
                List<LogEvent> events = new WindowsEventXmlSource().parse(file);
                for (LogEvent e : events) {
                    for (Finding f : engine.process(e)) {
                        bus.publish(f);
                        count++;
                    }
                }
                return new DetectionEngine.ReplayResult(events.size(), events.size(), 0, 0, count);
            }
            LogSource source = type.newSource(Clock.systemUTC(), serverZone, false);
            return engine.replay(file, source, bus::publish);
        });
    }

    /**
     * A new export in the watched Sysmon folder: like a replay, but only events newer than the ones already read from
     * earlier exports of the same computer (scheduled exports overlap, each holds the newest N events).
     */
    Future<DetectionEngine.ReplayResult> replaySysmonExport(Path file) {
        return scanPool.submit(() -> replaySysmon(file, true));
    }

    /** Sysmon exports go through the host detectors (HOST-xxx) with the current threat lists and rule switches. */
    private DetectionEngine.ReplayResult replaySysmon(Path file, boolean onlyNew) throws Exception {
        List<SysmonEvent> events = new SysmonXmlSource().parse(file);
        if (onlyNew) {
            events = newSinceLastExport(events);
        }
        HostDetectionEngine host = hostEngine();
        long count = 0;
        for (SysmonEvent e : events) {
            for (Finding f : host.process(e)) {
                bus.publish(f);
                count++;
            }
        }
        return new DetectionEngine.ReplayResult(events.size(), events.size(), 0, 0, count);
    }

    /**
     * Keeps the events newer than the newest one read from this computer's earlier exports, and remembers the new
     * newest time per computer in the settings (so it also holds after a restart). Events are sorted oldest first.
     */
    private List<SysmonEvent> newSinceLastExport(List<SysmonEvent> events) {
        Map<String, Instant> cutoff = new HashMap<>();
        Map<String, Instant> newest = new HashMap<>();
        List<SysmonEvent> fresh = new ArrayList<>();
        for (SysmonEvent e : events) {
            String key = SYSMON_SEEN + e.computer().toLowerCase(Locale.ROOT);
            if (e.timestamp().isAfter(cutoff.computeIfAbsent(key, this::seenUntil))) {
                fresh.add(e);
                newest.put(key, e.timestamp());
            }
        }
        newest.forEach((key, time) -> saveSetting(key, time.toString()));
        return fresh;
    }

    private Instant seenUntil(String key) {
        try {
            String saved = setting(key, "");
            return saved.isEmpty() ? Instant.MIN : Instant.parse(saved);
        } catch (DateTimeParseException damaged) {
            return Instant.MIN;                               // a damaged value only means: read everything once
        }
    }

    /** The host detectors with today's threat lists (IP/CIDR and DOMAIN indicators) and the look-alike checker. */
    private HostDetectionEngine hostEngine() throws SQLException, IOException {
        IocRepository iocs = new IocRepository(db);
        CidrSet[] intel = IntrusionSetup.threatIntel(iocs);
        Set<String> domains = iocs.values("DOMAIN");
        HostNetworkDetector network = new HostNetworkDetector(ip -> intel[0].contains(ip) || intel[1].contains(ip),
                domains::contains, lookalikes()::imitates);
        return new HostDetectionEngine(network, liveRules::enabled);
    }

    /** Watches monitor.sysmon.folder (if set) and replays each new .xml export once it stopped growing. */
    private void startSysmonWatcher() {
        String folder = config.get(SYSMON_FOLDER, "").trim();
        if (folder.isEmpty()) {
            return;
        }
        sysmonWatcher = new FolderWatcher(List.of(Path.of(folder)), quarantine.vault(), file -> {
            if (file.getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".xml")) {
                LOG.info("New Sysmon export: " + file);
                replaySysmonExport(file);
            }
        });
        sysmonWatcher.start();
    }

    /** Watches monitor.scan.folders (if set) and scans each new file once it stopped growing. Off by default. */
    private void startFolderWatcher() {
        List<Path> folders = new java.util.ArrayList<>();
        for (String part : config.get(SCAN_FOLDERS, "").split(",")) {
            if (!part.isBlank()) {
                folders.add(Path.of(part.trim()));
            }
        }
        if (folders.isEmpty()) {
            return;
        }
        folderWatcher = new FolderWatcher(folders, quarantine.vault(), file -> {
            LOG.info("New file in a watched folder: " + file);
            scanFile(file);
        });
        folderWatcher.start();
    }

    /**
     * Explains a finding on the scan pool. choice is ExplanationService.AUTO or a provider name; the result is never
     * an exception: failures fall back to the offline templates with the reason in Explanation.error().
     */
    public Future<ExplanationService.Explanation> explain(Finding finding, String choice) {
        return scanPool.submit(() -> explanations.explain(choice, finding));
    }

    /** The latest online/offline check, or empty when no cloud AI is configured (nothing to check). */
    public Optional<ConnectivityMonitor.Status> connectivityStatus() {
        return connectivity == null ? Optional.empty() : Optional.of(connectivity.current());
    }

    /** Called after every connectivity check (on the monitor thread). */
    public void addConnectivityListener(Consumer<ConnectivityMonitor.Status> listener) {
        if (connectivity != null) {
            connectivity.addListener(listener);
        }
    }

    /** The masked webhook address for display, or empty if none is configured. */
    public Optional<String> webhookTarget() {
        return webhook == null ? Optional.empty() : Optional.of(WebhookNotifier.mask(webhookUri()));
    }

    private URI webhookUri() {
        return URI.create(System.getenv(WEBHOOK_ENV).trim());
    }

    /** From AEGISLENS_WEBHOOK_URL (a secret, so never from the config file) and webhook.min.severity. */
    private WebhookNotifier buildWebhook() {
        String url = System.getenv(WEBHOOK_ENV);
        if (url == null || url.isBlank()) {
            return null;
        }
        try {
            Severity min = Severity.valueOf(config.get("webhook.min.severity", "HIGH").trim().toUpperCase(java.util.Locale.ROOT));
            return new WebhookNotifier(URI.create(url.trim()), min, Boolean.parseBoolean(config.get("webhook.allow.http", "false")),
                    http.client(), RetryPolicy.standard());
        } catch (IllegalArgumentException e) {
            LOG.warning("Webhook not started: " + e.getMessage());
            return null;
        }
    }

    private String settingOrNull(String key) {
        try {
            return settings.get(key).orElse(null);
        } catch (SQLException e) {
            return null;
        }
    }

    /** A user preference from the setting table (for example the UI theme), or fallback. */
    public String setting(String key, String fallback) {
        try {
            return settings.getOrDefault(key, fallback);
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Could not read setting " + key, e);
            return fallback;
        }
    }

    /** Stores a user preference; failures are logged (a preference is never worth crashing for). */
    public void saveSetting(String key, String value) {
        try {
            settings.put(key, value);
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Could not save setting " + key, e);
        }
    }

    /** Live sources and their counters (tailed files, syslog). */
    public List<MonitorManager.SourceStatus> monitorStatus() {
        return monitors.status();
    }

    /** Live Monitor view: tail one more SSH or web log (see MonitorManager.addFile). */
    public void addMonitorFile(Path file, LogType type, boolean fromStart) {
        monitors.addFile(file, type, fromStart);
    }

    /** Live Monitor view: stop tailing a file. */
    public boolean removeMonitorFile(Path file) throws InterruptedException {
        return monitors.removeFile(file);
    }

    /** The shared detection engine (the live monitors use it too). */
    public DetectionEngine engine() {
        return engine;
    }

    /** Starts the persister and schedules the daily maintenance. Call once. */
    public synchronized void start() {
        if (started || shutDown) {
            throw new IllegalStateException(shutDown ? "already shut down" : "already started");
        }
        started = true;
        persister.start();
        if (connectivity != null) {
            connectivity.start();
        }
        if (webhook != null) {
            persister.addListener(webhook::offer);
        }
        try {
            monitors.start();
            startFolderWatcher();
            startSysmonWatcher();
        } catch (IOException e) {
            LOG.log(Level.WARNING, "Could not start live monitoring (for example a syslog port is in use)", e);
        }
        maintenance.scheduleAtFixedRate(this::runMaintenance, FIRST_MAINTENANCE_DELAY.toMinutes(),
                MAINTENANCE_PERIOD.toMinutes(), TimeUnit.MINUTES);
        if (!"false".equalsIgnoreCase(config.get("feeds.enabled", "true"))) {      // feeds.enabled=false: never download
            feedScheduler.scheduleAtFixedRate(this::refreshDueFeeds, FIRST_FEED_CHECK.toSeconds(), FEED_CHECK_PERIOD.toSeconds(),
                    TimeUnit.SECONDS);
        }
    }

    /** Feed list: bundled defaults overlaid by the data folder's feeds.properties (empty if unreadable). */
    private List<FeedDefinition> loadFeeds() {
        try {
            return FeedCatalog.load(config.paths().dataDir());
        } catch (IOException e) {
            LOG.log(Level.WARNING, "Could not read the feed list; threat feeds are off", e);
            return List.of();
        }
    }

    /** Hourly: update the feeds that are due and, if anything changed, give the detectors the new lists. */
    private void refreshDueFeeds() {
        try {
            if (feeds.updateDue().stream().anyMatch(r -> r.outcome() == FeedUpdater.Outcome.UPDATED)) {
                reloadThreatIntel();
            }
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "Feed check failed", e);          // a scheduled task must never die silently
        } finally {
            notifyIntelListeners();                                   // status, age and errors changed either way
        }
    }

    /** Tools > Update threat feeds now (still respects each feed's minimum interval). */
    public Future<List<FeedUpdater.Result>> updateFeedsNow() {
        return feedScheduler.submit(() -> {
            List<FeedUpdater.Result> results = feeds.updateAllNow();
            if (results.stream().anyMatch(r -> r.outcome() == FeedUpdater.Outcome.UPDATED)) {
                reloadThreatIntel();
            }
            notifyIntelListeners();
            return results;
        });
    }

    /** Loads the IP/CIDR indicators into the live detectors (NET-005) without restarting anything. */
    void reloadThreatIntel() {
        try {
            CidrSet[] intel = IntrusionSetup.threatIntel(new IocRepository(db));
            engine.updateThreatIntel(intel[0], intel[1]);
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Could not reload threat-intelligence lists", e);
        }
        notifyIntelListeners();
    }

    /** Called after every feed check and every change to the indicator lists (on that thread: use Platform.runLater). */
    public void addIntelListener(Runnable listener) {
        intelListeners.add(listener);
    }

    private void notifyIntelListeners() {
        for (Runnable l : intelListeners) {
            try {
                l.run();
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "Threat-intel listener failed", e);
            }
        }
    }

    public List<FeedUpdater.Status> feedStatus() {
        return feeds.status();
    }

    public boolean virusTotalEnabled() {
        return virusTotal.enabled();
    }

    public int virusTotalQueued() {
        return virusTotal.queued();
    }

    /**
     * Asks VirusTotal about a scanned file (only its SHA-256 is sent). If enough engines flag it, a MAL-005 finding is
     * published like any other. The future fails with VirusTotalClient.VtException (no key, quota, ...).
     */
    public CompletableFuture<VtResult> checkVirusTotal(ScanResult result) {
        String target = result.path() != null ? result.path() : result.name();
        return virusTotal.lookup(result.sha256()).thenApply(vt -> {
            VirusTotalClient.finding(vt, target, malwareThreshold()).ifPresent(f -> {
                try {
                    bus.publish(f);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            return vt;
        });
    }

    /** MAL-005's threshold from the rule table (default 1 engine). */
    private int malwareThreshold() {
        return (int) Math.round(liveRules.threshold(VirusTotalClient.RULE, 1));
    }

    /** Settings > rules: applies rule on/off and thresholds at once to the log detectors and the file scanner. */
    public void reloadRules() throws SQLException {
        RuleRepository repo = new RuleRepository(db);
        liveRules.reload(repo);
        engine.reconfigure(IntrusionSetup.thresholds(repo, config));
    }

    private void loadRules() {
        try {
            liveRules.reload(new RuleRepository(db));
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Could not read the rule table; every malware rule stays on with its default", e);
        }
    }

    /** Hands a finding to the pipeline; waits if the bus is full. */
    public void publish(Finding finding) throws InterruptedException {
        bus.publish(finding);
    }

    /** One sandbox run: what the program did (output, created files, exit) and the SBX findings (already published). */
    public record SandboxRun(SandboxReport report, List<Finding> findings) {
    }

    /** Runs one of the team's own demo programs in the local sandbox (never a file: the type is an enum). */
    public Future<SandboxRun> runDemo(DemoProgram demo) {
        return scanPool.submit(() -> publishRun(new LocalSandbox().run(demo)));
    }

    /** The container sandbox's state for the Sandbox view: "off", "no engine" or "ready". */
    public String containerState() {
        ContainerSandbox box = ContainerSandbox.fromEnvironment();
        if (!box.isEnabled()) {
            return "off";
        }
        return box.engineAvailable() ? "ready" : "no engine";
    }

    /**
     * Runs a sample inside a locked-down container (README: Security and safety): only when AEGISLENS_ENABLE_REAL_SANDBOX=1 and an engine
     * answers; ContainerSandbox refuses everything else itself, so this is a second check, not the only one.
     */
    public Future<SandboxRun> runInContainer(Path sample) {
        return scanPool.submit(() -> publishRun(ContainerSandbox.fromEnvironment().run(sample)));
    }

    private SandboxRun publishRun(SandboxReport report) throws InterruptedException {
        List<Finding> found = new ArrayList<>(BehaviourFindings.from(report));
        found.removeIf(f -> !liveRules.enabled(f.ruleId()));
        for (Finding f : found) {
            bus.publish(f);
        }
        return new SandboxRun(report, List.copyOf(found));
    }

    /** One URL check: the findings (already published) and, when the page was fetched, what the fetch saw. */
    public record WebCheck(String url, List<Finding> findings, HeaderChecker.Result fetched) {
    }

    /**
     * Checks a URL statically (WEB-001, WEB-002, WEB-004) and, only when fetch is true (the user agreed), fetches it
     * once through the SSRF guard for missing headers (WEB-003) and page content (WEB-005). Findings of rules that are
     * switched off are dropped; the rest go through the AlertBus like every other finding.
     */
    public Future<WebCheck> checkUrl(String url, boolean fetch) {
        return scanPool.submit(() -> {
            List<Finding> found = new ArrayList<>(urlAnalyzer().analyze(url));
            HeaderChecker.Result fetched = null;
            if (fetch) {
                fetched = new HeaderChecker().fetch(url);
                HeaderChecker.headerFinding(fetched).ifPresent(found::add);
                found.addAll(new HtmlAnalyzer().analyze(fetched.html(), fetched.finalUrl()));
            }
            found.removeIf(f -> !liveRules.enabled(f.ruleId()));
            for (Finding f : found) {
                bus.publish(f);
            }
            return new WebCheck(url, List.copyOf(found), fetched);
        });
    }

    /** The static URL checks with the current WEB-002 pattern and the threat lists in the database. */
    private UrlAnalyzer urlAnalyzer() throws IOException {
        IocRepository iocs = new IocRepository(db);
        return new UrlAnalyzer(lookalikes(), new InjectionPatterns(liveRules.pattern("WEB-002", Thresholds.DEFAULT_INJECTION)),
                value -> {
                    try {
                        return iocs.exists("DOMAIN", value) || iocs.exists("URL", value);
                    } catch (SQLException e) {
                        return false;                        // a DB problem never blocks the static checks
                    }
                });
    }

    private synchronized LookalikeChecker lookalikes() throws IOException {
        if (lookalikes == null) {
            lookalikes = LookalikeChecker.bundled();
        }
        return lookalikes;
    }

    /**
     * Analyses one file on the scan pool (bytes are only read, never executed): saves a file report, publishes the
     * findings, and returns the full result for the Malware view. Throws (inside the Future) for unreadable files.
     */
    public Future<ScanResult> scanFile(Path file) {
        return scanPool.submit(() -> {
            ScanResult r = scanner.scan(file);
            record(List.of(r), "file " + file.getFileName());
            return r;
        });
    }

    /** Scans every file in a folder (sub-folders too when recursive); failed files come back as failed results. */
    public Future<List<ScanResult>> scanFolder(Path folder, boolean recursive) {
        return scanPool.submit(() -> {
            List<ScanResult> results = scanner.scan(folder, recursive);
            record(results, "folder " + folder.getFileName());
            return results;
        });
    }

    /** One MALWARE scan session per scan action: a file report per analysed file, findings into the pipeline. */
    private void record(List<ScanResult> results, String target) throws SQLException, InterruptedException {
        ScanSessionRepository sessions = new ScanSessionRepository(db);
        long session = sessions.begin("MALWARE", target);
        FileReportRepository reports = new FileReportRepository(db);
        for (ScanResult r : results) {
            if (!r.ok()) {
                continue;
            }
            reports.save(new FileReport(session, r.path() != null ? r.path() : r.name(), r.fileType(), r.size(), r.md5(),
                    r.sha256(), r.entropy(), r.risk()), session);
            for (Finding f : r.findings()) {
                bus.publish(f);
            }
        }
        sessions.finish(session, true);
    }

    /** True if the SHA-256 is a known-bad hash in the ioc table (MAL-004). A DB error counts as "not known". */
    private boolean isKnownBadHash(String sha256) {
        try {
            return new IocRepository(db).exists("HASH", sha256);
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "IOC lookup failed", e);
            return false;
        }
    }

    /**
     * The last saved file scans, rebuilt from file_report and their findings, so the Malware view is not empty after a
     * restart. Parser details (sections, imports) are not stored, so these show hashes, entropy, risk and findings.
     */
    public List<ScanResult> recentScans(int limit) throws SQLException {
        FindingRepository findings = new FindingRepository(db);
        List<ScanResult> list = new ArrayList<>();
        for (FileReport r : new FileReportRepository(db).findRecent(limit)) {
            Path p = Path.of(r.path());
            String name = p.getFileName() == null ? r.path() : p.getFileName().toString();
            Map<String, String> details = new LinkedHashMap<>();
            details.put("File|Scanned at", r.scannedAt() == null ? "" : r.scannedAt().toString());
            details.put("Hashes|MD5", r.md5());
            details.put("Hashes|SHA-256", r.sha256());
            list.add(new ScanResult(name, r.path(), r.fileType(), r.sizeBytes(), r.md5(), r.sha256(), r.entropy(),
                    r.riskScore(), findings.findByTarget(r.path(), 50), details, null));
        }
        return list;
    }

    /** Moves a file into the quarantine vault (manual action, the UI confirms first). Returns the quarantine id. */
    public long quarantine(Path file, String reason) throws IOException, SQLException {
        return quarantine.quarantine(file, reason);
    }

    /** Restores a quarantined file and returns where it was put. */
    public Path restore(long quarantineId) throws IOException, SQLException {
        return quarantine.restore(quarantineId);
    }

    /** Quarantine records, newest first. */
    public List<QuarantineEntry> quarantined() throws SQLException {
        return new QuarantineRepository(db).findAll();
    }

    /** Called for every saved finding, on the persister thread (the UI must switch threads with Platform.runLater). */
    public void addListener(Consumer<Finding> listener) {
        persister.addListener(listener);
    }

    /** Re-reads the allow-list setting (after the user changed it). */
    public void reloadAllowList() throws SQLException {
        persister.setAllowList(loadAllowListOrThrow());
    }

    /** Retention clean-up and (for the real data folder) a dated backup. Errors are logged, never thrown. */
    void runMaintenance() {
        try {
            RetentionJob.Result result = new RetentionJob(db).runOnce(Instant.now());
            LOG.info("Retention: " + result);
            if (app != null) {
                new BackupService(db).backup(config.paths().backupsDir(), LocalDate.now(ZoneOffset.UTC));
            }
        } catch (SQLException | IOException | RuntimeException e) {
            LOG.log(Level.WARNING, "Daily maintenance failed", e);
        }
    }

    /** Stops everything in a safe order. Safe to call more than once. Closes the database only if this class opened it. */
    public synchronized void shutdown() throws InterruptedException {
        if (shutDown) {
            return;
        }
        shutDown = true;
        monitors.stop();                                  // no new findings from live sources
        for (FolderWatcher w : new FolderWatcher[] {folderWatcher, sysmonWatcher}) {
            if (w != null) {
                w.stopWatching();
                w.join(SHUTDOWN_WAIT.toMillis());
            }
        }
        stopPool(scanPool);
        stopPool(maintenance);
        stopPool(feedScheduler);
        virusTotal.close();
        if (connectivity != null) {
            connectivity.stopMonitoring();
            connectivity.join(SHUTDOWN_WAIT.toMillis());
        }
        if (webhook != null) {
            webhook.close();
        }
        bus.close();
        if (started) {
            persister.join(SHUTDOWN_WAIT.toMillis());
        }
        http.close();                                     // releases the shared HTTP connections (N19)
        if (app != null) {
            try {
                app.close();
            } catch (SQLException | IOException e) {
                LOG.log(Level.WARNING, "Closing the database failed", e);
            }
        }
    }

    @Override
    public void close() throws InterruptedException {
        shutdown();
    }

    /** A message for the user if the database had to be replaced at start. */
    public Optional<String> warning() {
        return app == null ? Optional.empty() : app.warning();
    }

    public Database database() {
        return db;
    }

    public ExplanationService explanations() {
        return explanations;
    }

    public PersisterThread persister() {
        return persister;
    }

    public AppConfig config() {
        return config;
    }

    private AllowList loadAllowList() {
        try {
            return loadAllowListOrThrow();
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Could not read the allow-list; starting with an empty one", e);
            return AllowList.parse("");
        }
    }

    private AllowList loadAllowListOrThrow() throws SQLException {
        return AllowList.parse(settings.getOrDefault(AllowList.SETTING, ""));
    }

    private static void stopPool(ExecutorService pool) throws InterruptedException {
        pool.shutdown();
        if (!pool.awaitTermination(SHUTDOWN_WAIT.toMillis(), TimeUnit.MILLISECONDS)) {
            pool.shutdownNow();
        }
    }

    /** Names pool threads aegislens-scan-1, ... (easy to spot in a thread dump); background maintenance runs at MIN_PRIORITY. */
    private static ThreadFactory named(String role, int priority) {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread t = new Thread(runnable, THREAD_PREFIX + role + "-" + counter.incrementAndGet());
            t.setDaemon(true);
            t.setPriority(priority);
            return t;
        };
    }
}
