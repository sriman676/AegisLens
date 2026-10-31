package com.aegislens.ui;

import com.aegislens.app.AnalystActions;
import com.aegislens.app.AppConfig;
import com.aegislens.app.Branding;
import com.aegislens.app.HeadlessMain;
import com.aegislens.app.LoggingSetup;
import com.aegislens.app.ScanCoordinator;
import com.aegislens.db.AlreadyRunningException;
import com.aegislens.db.BackupService;
import com.aegislens.db.DataExchange;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.stage.WindowEvent;
import javafx.stage.Screen;
import javafx.scene.input.KeyCombination;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.control.RadioMenuItem;
import javafx.scene.control.SeparatorMenuItem;
import javafx.scene.control.ToggleButton;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.ToolBar;
import javafx.scene.control.Separator;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;

import java.awt.GraphicsEnvironment;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * JavaFX application: init() opens the data folder and starts the pipeline, start() builds the branded window
 * (menu bar, left sidebar navigation, content area with the Dashboard), stop() shuts the pipeline down.
 * Two designs, DARK and LIGHT, are switched from View > Theme or the sidebar button and remembered in the settings.
 * Scan and replay work runs on the coordinator's pool, never on the FX thread. Business logic stays out of this
 * package: it talks only to ScanCoordinator and DashboardPresenter.
 */
public class AegisLensApp extends Application {

    private static final int[] ICON_SIZES = {16, 32, 48, 64, 128, 256};
    private static final Logger LOG = Logger.getLogger(AegisLensApp.class.getName());

    private ScanCoordinator coordinator;
    private String startupError;
    private volatile DashboardView dashboard;           // volatile: read by the persister thread in onFinding
    private MalwareView malware;
    private FindingsView findings;
    private ReportsView reports;
    private volatile IntrusionView intrusion;
    private volatile CriticalToast toast;
    private final LiveRefresh liveFindings = new LiveRefresh(this::showNewFindings);
    private final LiveRefresh liveIntel = new LiveRefresh(() -> this.intel.refresh());
    private IntelView intel;
    private AiView ai;
    private WebCheckView web;
    private Stage stage;
    private Scene scene;
    private Theme theme = Theme.DARK;
    private final StackPane content = new StackPane();
    private final Map<String, Node> views = new LinkedHashMap<>();
    private final ToggleGroup nav = new ToggleGroup();
    private final ToggleGroup themeChoice = new ToggleGroup();
    private Button themeButton;
    private volatile String current = "Dashboard";
    private final Label bannerText = new Label();
    private final HBox banner = new HBox(10);

    /** Runs on the JavaFX launcher thread before the window exists: no UI calls here, only remember the outcome. */
    @Override
    public void init() {
        try {
            AppConfig config = AppConfig.load(getParameters().getRaw().toArray(new String[0]));
            LoggingSetup.install(config.paths().logsDir());
            coordinator = new ScanCoordinator(config);
            coordinator.start();
            theme = Theme.fromSetting(coordinator.setting(Theme.SETTING, Theme.DARK.name()));
            LOG.info("AegisLens started, data folder " + config.paths().dataDir());
        } catch (AlreadyRunningException e) {
            startupError = "AegisLens is already running. Use the window that is already open.";
        } catch (Exception e) {                       // any other start-up failure: show it instead of a silent crash
            LOG.log(Level.SEVERE, "Start-up failed", e);
            startupError = "AegisLens could not start: " + e.getMessage();
        }
    }

    @Override
    public void start(Stage stage) {
        this.stage = stage;
        addIcons(stage);
        if (startupError != null) {
            styled(new Alert(Alert.AlertType.ERROR, startupError)).showAndWait();
            Platform.exit();
            return;
        }
        toast = new CriticalToast(stage);
        scene = new Scene(buildRoot(), 1360, 860);
        listenTo(coordinator);                               // after buildRoot: the views exist
        applyTheme(theme);
        String lastView = coordinator.setting(WindowState.VIEW_SETTING, "Dashboard");
        show(views.containsKey(lastView) ? lastView : "Dashboard");
        stage.setTitle(Messages.text("app.title"));
        stage.setScene(scene);
        stage.setMinWidth(WindowState.MIN_WIDTH);
        stage.setMinHeight(WindowState.MIN_HEIGHT);
        WindowState.parse(coordinator.setting(WindowState.SETTING, null)).filter(this::onAScreen).ifPresent(this::restore);
        stage.setOnCloseRequest(this::confirmClose);
        Thread.setDefaultUncaughtExceptionHandler(this::uncaught);
        stage.show();
        dashboard.start();
        coordinator.warning().ifPresent(text -> styled(new Alert(Alert.AlertType.WARNING, text)).show());
    }

    // ---------------------------------------------------------------- layout

    /** Builds every view for the current coordinator, and the window layout around them. */
    private BorderPane buildRoot() {
        Ui.setScale(appearance().fontSize());
        toast.setEnabled(!"false".equals(coordinator.setting(CriticalToast.SETTING, "true")));
        ImageView brandLogo = logo(36);
        views.clear();
        nav.getToggles().clear();                      // a restart builds new buttons and menu items
        themeChoice.getToggles().clear();
        dashboard = new DashboardView(new DashboardPresenter(coordinator), brandLogo);
        views.put("Dashboard", dashboard.node());
        malware = new MalwareView(coordinator, stage, d -> styled(d));
        views.put("Malware", malware.node());
        ai = new AiView(coordinator);
        views.put("AI", ai.node());
        findings = new FindingsView(coordinator, stage, d -> styled(d), id -> {
            show("AI");
            ai.explainFinding(id);
        });
        views.put("Findings", findings.node());
        reports = new ReportsView(coordinator);
        views.put("Reports", reports.node());
        views.put("SQL", new SqlView(coordinator).node());
        intrusion = new IntrusionView(coordinator, stage);
        views.put("Intrusion", intrusion.node());
        web = new WebCheckView(coordinator, stage, d -> styled(d));
        views.put("Web", web.node());
        views.put("Sandbox", new SandboxView(coordinator, stage, d -> styled(d)).node());
        intel = new IntelView(coordinator, stage, this::restart);
        views.put("Intel", intel.node());
        views.put("Settings", new SettingsView(coordinator, new SettingsView.Host() {
            @Override
            public void restart() {
                AegisLensApp.this.restart();
            }

            @Override
            public void appearanceChanged() {
                rebuild();                                 // new column widths need new views; services keep running
            }
        }).node());

        BorderPane root = new BorderPane();
        root.setTop(menuBar());
        root.setLeft(sidebar(brandLogo));
        VBox.setVgrow(content, Priority.ALWAYS);
        root.setCenter(new VBox(banner(), toolBar(), content));
        return root;
    }

    /**
     * New findings and threat-intel changes update the screens by themselves (no Refresh button): the listeners are added
     * once per coordinator and forward to whichever views exist now, so rebuilt views never leave old listeners behind.
     */
    private void listenTo(ScanCoordinator c) {
        c.addListener(f -> {
            dashboard.onFinding(f);
            intrusion.onFinding(f);
            toast.offer(f);
            liveFindings.poke();
        });
        c.addIntelListener(liveIntel::poke);
    }

    /** On the FX thread, at most every 400 ms. Only the visible screen reloads; the others reload when shown. */
    private void showNewFindings() {
        reload(current);
    }

    /** Builds the views again for the current coordinator and look, and shows the same view as before. */
    private void rebuild() {
        dashboard.stop();
        intrusion.stop();
        scene.setRoot(buildRoot());
        applyTheme(theme);
        show(current);
        dashboard.start();
    }

    /**
     * Settings > Restart now: stops every service, reloads the configuration and starts again inside this window. A new
     * process is never started (only the sandbox package may do that), so the window, position and theme stay.
     */
    private void restart() {
        dashboard.stop();
        intrusion.stop();
        content.getChildren().setAll(new Label("Restarting…"));
        UiTasks.run("restart", () -> {
            coordinator.shutdown();
            ScanCoordinator fresh = new ScanCoordinator(AppConfig.load(getParameters().getRaw().toArray(new String[0])));
            fresh.start();
            return fresh;
        }, fresh -> {
            coordinator = fresh;
            listenTo(fresh);
            rebuild();
            LOG.info("AegisLens restarted with the saved settings");
        }, e -> styled(new Alert(Alert.AlertType.ERROR, "Restart failed: " + e.getMessage()
                + ". Close AegisLens and start it again.")).show());
    }

    private MenuBar menuBar() {
        MenuItem exportCsv = item("menu.file.exportCsv", "Shortcut+E");
        exportCsv.setOnAction(e -> { show("Findings"); findings.exportFindings(DataExchange.Format.CSV); });
        MenuItem exportJson = item("menu.file.exportJson", null);
        exportJson.setOnAction(e -> { show("Findings"); findings.exportFindings(DataExchange.Format.JSON); });
        MenuItem importCsv = item("menu.file.import", "Shortcut+I");
        importCsv.setOnAction(e -> { show("Findings"); findings.importFindings(); });
        MenuItem report = item("menu.file.report", null);
        report.setOnAction(e -> { show("Findings"); findings.exportReport(); });
        MenuItem blocklist = item("menu.file.blocklist", null);
        blocklist.setOnAction(e -> { show("Intel"); intel.exportBlocklist(); });
        MenuItem backup = item("menu.file.backup", null);
        backup.setOnAction(e -> backupDatabase());
        MenuItem exit = item("menu.file.exit", "Shortcut+Q");
        exit.setOnAction(e -> stage.fireEvent(new WindowEvent(stage, WindowEvent.WINDOW_CLOSE_REQUEST)));   // same check as the X
        Menu file = new Menu(Messages.text("menu.file"), null, exportCsv, exportJson, report, importCsv, new SeparatorMenuItem(), blocklist, backup,
                new SeparatorMenuItem(), exit);

        MenuItem scanFolder = item("menu.scan.folder", "Shortcut+Shift+O");
        scanFolder.setOnAction(e -> { show("Malware"); malware.chooseAndScanFolder(); });
        MenuItem scanFile = item("menu.scan.file", "Shortcut+O");
        scanFile.setOnAction(e -> scanFile());
        MenuItem replay = item("menu.scan.replay", "Shortcut+R");
        replay.setOnAction(e -> replayLog());
        MenuItem url = item("menu.scan.url", "Shortcut+L");
        url.setOnAction(e -> {
            show("Web");
            web.focus();
        });
        Menu scan = new Menu(Messages.text("menu.scan"), null, scanFile, scanFolder, replay, url);

        Menu themes = new Menu(Messages.text("menu.view.theme"));
        for (Theme t : Theme.values()) {
            RadioMenuItem item = new RadioMenuItem(t.label());
            item.setToggleGroup(themeChoice);
            item.setUserData(t);
            item.setSelected(t == theme);
            item.setOnAction(e -> applyTheme(t));
            themes.getItems().add(item);
        }
        MenuItem refresh = item("menu.view.refresh", "F5");
        refresh.setOnAction(e -> refreshCurrent());
        Menu view = new Menu(Messages.text("menu.view"), null, themes, refresh, new SeparatorMenuItem(),
                navItem("Dashboard"), navItem("Findings"), navItem("Reports"));

        MenuItem console = item("menu.tools.console", null);
        console.setOnAction(e -> openConsole());
        MenuItem feeds = item("menu.tools.feeds", null);
        feeds.setOnAction(e -> {
            show("Intel");
            intel.updateNow();
        });
        Menu tools = new Menu(Messages.text("menu.tools"), null, feeds, console);

        MenuItem about = new MenuItem(Messages.text("menu.help.about"), logo(16));     // MenuItem with an image
        about.setOnAction(e -> about());
        Menu help = new Menu(Messages.text("menu.help"), null, about);
        return new MenuBar(file, scan, view, tools, help);
    }

    private MenuItem navItem(String name) {
        MenuItem item = new MenuItem(Messages.text("menu.view.goto", Messages.text("nav." + name)));
        item.setOnAction(e -> show(name));
        return item;
    }

    /** A menu item with its text from messages.properties and an optional shortcut such as "Shortcut+O" (Ctrl or Cmd). */
    private static MenuItem item(String key, String shortcut) {
        MenuItem item = new MenuItem(Messages.text(key));
        if (shortcut != null) {
            item.setAccelerator(KeyCombination.keyCombination(shortcut));
        }
        return item;
    }

    private VBox sidebar(ImageView brandLogo) {
        Label aegis = new Label("Aegis");
        aegis.getStyleClass().add("brand");
        Label lens = new Label("Lens");
        lens.getStyleClass().add("brand-accent");
        Label tag = new Label(Messages.text("app.tagline"));
        tag.getStyleClass().add("brand-tag");
        HBox brand = new HBox(10, brandLogo, new VBox(-2, new HBox(aegis, lens), tag));
        brand.setAlignment(Pos.CENTER_LEFT);

        VBox side = new VBox(brand, section("nav.monitor"), navButton("Dashboard", Icons.DASHBOARD),
                navButton("Intrusion", Icons.INTRUSION), navButton("Malware", Icons.MALWARE), navButton("Web", Icons.WEB),
                navButton("Sandbox", Icons.SANDBOX),
                section("nav.investigate"), navButton("Findings", Icons.FINDINGS), navButton("Reports", Icons.REPORTS),
                navButton("SQL", Icons.SQL), navButton("AI", Icons.AI),
                section("nav.system"), navButton("Intel", Icons.INTEL), navButton("Settings", Icons.SETTINGS));
        side.getStyleClass().add("sidebar");
        nav.selectedToggleProperty().addListener((obs, old, now) -> {
            if (now == null) {
                nav.selectToggle(old);                   // a sidebar always has one view selected
            }
        });

        Region spacer = new Region();
        VBox.setVgrow(spacer, Priority.ALWAYS);
        Button scanFile = new Button(Messages.text("action.scanFile"));
        scanFile.getStyleClass().add("action-button");
        scanFile.setOnAction(e -> scanFile());
        Button replay = new Button(Messages.text("action.replay"));
        replay.getStyleClass().add("ghost-button");
        replay.setOnAction(e -> replayLog());
        themeButton = new Button();
        themeButton.getStyleClass().add("ghost-button");
        themeButton.setOnAction(e -> applyTheme(theme == Theme.DARK ? Theme.LIGHT : Theme.DARK));
        Label mode = new Label(AiPresenter.connectivityText(coordinator.connectivityStatus()));
        mode.getStyleClass().addAll("mode-chip", AiPresenter.connectivityClass(coordinator.connectivityStatus()));
        coordinator.addConnectivityListener(status -> Platform.runLater(() -> {      // monitor thread -> FX thread
            mode.setText(AiPresenter.connectivityText(java.util.Optional.of(status)));
            mode.getStyleClass().removeAll("online", "offline", "checking");
            mode.getStyleClass().add(AiPresenter.connectivityClass(java.util.Optional.of(status)));
        }));
        VBox actions = new VBox(8, scanFile, replay, themeButton, mode);
        side.getChildren().addAll(spacer, actions);
        return side;
    }

    /** Quick actions above every view. */
    private ToolBar toolBar() {
        Button scanFile = new Button(Messages.text("action.scanFile"), Icons.icon(Icons.MALWARE, 14));
        scanFile.setOnAction(e -> scanFile());
        Button replay = new Button(Messages.text("action.replay"), Icons.icon(Icons.INTRUSION, 14));
        replay.setOnAction(e -> replayLog());
        Button findings = new Button(Messages.text("action.findings"), Icons.icon(Icons.FINDINGS, 14));
        findings.setOnAction(e -> show("Findings"));
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        Label hint = new Label(Messages.text("app.hint"));
        hint.getStyleClass().add("page-subtitle");
        return new ToolBar(scanFile, replay, new Separator(), findings, spacer, hint);
    }

    private ToggleButton navButton(String name, String iconPath) {
        ToggleButton b = new ToggleButton(Messages.text("nav." + name), Icons.icon(iconPath, 18));
        b.setAccessibleText(Messages.text("nav." + name));
        b.getStyleClass().add("nav-button");
        b.setToggleGroup(nav);
        b.setUserData(name);
        b.setMaxWidth(Double.MAX_VALUE);
        b.setOnAction(e -> show(name));
        return b;
    }

    private static Label section(String key) {
        Label l = new Label(Messages.text(key));
        l.getStyleClass().add("nav-section");
        return l;
    }

    /** Shows one view in the content area and highlights its sidebar button. */
    private void show(String name) {
        content.getChildren().setAll(views.get(name));
        reload(name);                                    // new findings may have arrived since it was last shown
        nav.getToggles().stream().filter(t -> name.equals(t.getUserData())).findFirst().ifPresent(nav::selectToggle);
        current = name;
    }

    /** Loads the newest data into one view (the views that list findings or feeds). */
    private void reload(String name) {
        switch (name) {
            case "Dashboard" -> dashboard.refreshNow();
            case "Findings" -> findings.refresh();
            case "Reports" -> reports.refresh();
            case "AI" -> ai.reload();
            case "Intel" -> intel.refresh();
            default -> { }
        }
    }

    /** View > Refresh (F5): reloads the visible view. */
    private void refreshCurrent() {
        show(current);
    }

    /** Switches design (stylesheet), updates the menu, the sidebar button and remembers the choice. */
    private void applyTheme(Theme t) {
        theme = t;
        scene.getStylesheets().setAll(css(t));
        scene.getRoot().setStyle(appearance().rootStyle(t));
        themeChoice.getToggles().stream().filter(x -> x.getUserData() == t).findFirst().ifPresent(themeChoice::selectToggle);
        if (themeButton != null) {
            Theme next = t == Theme.DARK ? Theme.LIGHT : Theme.DARK;
            themeButton.setText(Messages.text("theme.switchTo", next.label()));
            themeButton.setGraphic(Icons.icon(next == Theme.LIGHT ? Icons.SUN : Icons.MOON, 16));
        }
        coordinator.saveSetting(Theme.SETTING, t.name());
    }

    /** Accent colour and font size from Settings > Appearance (validated in Appearance). */
    private Appearance appearance() {
        return Appearance.of(coordinator.setting(Appearance.ACCENT_SETTING, null), coordinator.setting(Appearance.FONT_SETTING, null));
    }

    private String css(Theme t) {
        return getClass().getResource(t.stylesheet()).toExternalForm();
    }

    // ---------------------------------------------------------------- actions

    /** Scan > Scan file...: static analysis only (the file is read, never run). */
    private void scanFile() {
        show("Malware");
        malware.chooseAndScanFile();
    }

    /** Scan > Replay log...: the Intrusion view chooses the file and shows the result. */
    private void replayLog() {
        show("Intrusion");
        intrusion.chooseAndReplay();
    }

    private void about() {
        Alert a = styled(new Alert(Alert.AlertType.INFORMATION));
        a.setTitle("About AegisLens");
        Branding brand = Branding.load(coordinator);
        a.setHeaderText((brand.name().isBlank() ? "" : brand.name() + " · ") + "AegisLens " + HeadlessMain.VERSION
                + " - defensive security workbench");
        a.setContentText("Static malware analysis, log-based intrusion detection and AI explanations.\nWorks fully offline.");
        a.setGraphic(brand.logo() == null ? logo(64)
                : new ImageView(new Image(new ByteArrayInputStream(brand.logo()), 64, 64, true, true)));
        a.show();
    }

    @Override
    public void stop() throws InterruptedException {
        if (dashboard != null) {
            dashboard.stop();
            intrusion.stop();
        }
        if (coordinator != null) {
            coordinator.shutdown();
            LOG.info("AegisLens stopped");
        }
        LoggingSetup.uninstall();
    }

    /** Tools > Analyst Console: the AWT window, unless there is no display for AWT. */
    private void openConsole() {
        if (GraphicsEnvironment.isHeadless()) {
            styled(new Alert(Alert.AlertType.INFORMATION, "The AWT console needs a desktop session.")).show();
            return;
        }
        AnalystConsoleFrame.showFor(new AnalystActions(coordinator));
    }

    // ---------------------------------------------------------------- window, close and errors

    /** A hidden bar above the toolbar that shows unexpected errors without blocking the window (G6). */
    private HBox banner() {
        Button dismiss = new Button(Messages.text("error.dismiss"));
        dismiss.getStyleClass().add("secondary-button");
        dismiss.setOnAction(e -> showBanner(false));
        bannerText.setWrapText(true);
        HBox.setHgrow(bannerText, Priority.ALWAYS);
        banner.getChildren().setAll(Icons.icon(Icons.CRITICAL, 18), bannerText, dismiss);
        banner.getStyleClass().add("error-banner");
        banner.setAlignment(Pos.CENTER_LEFT);
        showBanner(false);
        return banner;
    }

    private void showBanner(boolean visible) {
        banner.setVisible(visible);
        banner.setManaged(visible);
    }

    /** Any thread's uncaught exception: logged with its stack trace, shown to the user as one readable line. */
    private void uncaught(Thread thread, Throwable error) {
        LOG.log(Level.SEVERE, "Uncaught exception in " + thread.getName(), error);
        String what = SafeText.shorten(error.getClass().getSimpleName() + ": " + error.getMessage());
        Platform.runLater(() -> {
            bannerText.setText(Messages.text("error.banner", what));
            showBanner(true);
        });
    }

    /** Asks before closing while live sources are watched (G3), then remembers window and view (G12). */
    private void confirmClose(WindowEvent event) {
        int sources = coordinator.monitorStatus().size();
        if (sources > 0) {
            Alert ask = styled(new Alert(Alert.AlertType.CONFIRMATION, Messages.text("close.monitoring", sources),
                    ButtonType.OK, ButtonType.CANCEL));
            ((Button) ask.getDialogPane().lookupButton(ButtonType.OK)).setDefaultButton(false);       // G18: Cancel is the default
            ((Button) ask.getDialogPane().lookupButton(ButtonType.CANCEL)).setDefaultButton(true);
            if (ask.showAndWait().filter(b -> b == ButtonType.OK).isEmpty()) {
                event.consume();
                return;
            }
        }
        coordinator.saveSetting(WindowState.SETTING, new WindowState(stage.getX(), stage.getY(), stage.getWidth(),
                stage.getHeight(), stage.isMaximized()).toString());
        coordinator.saveSetting(WindowState.VIEW_SETTING, current);
        stage.close();                    // File > Exit only fires the event; closing an already closing window is harmless
    }

    /** True if the saved window would be at least partly visible (a monitor may have been unplugged). */
    private boolean onAScreen(WindowState w) {
        return !Screen.getScreensForRectangle(w.x(), w.y(), w.width(), w.height()).isEmpty();
    }

    private void restore(WindowState w) {
        stage.setX(w.x());
        stage.setY(w.y());
        stage.setWidth(w.width());
        stage.setHeight(w.height());
        stage.setMaximized(w.maximized());
    }

    // ---------------------------------------------------------------- helpers

    /** Gives a dialog the current design. */
    private <D extends Dialog<?>> D styled(D dialog) {
        dialog.getDialogPane().getStylesheets().add(css(theme));
        dialog.getDialogPane().setStyle(appearance().rootStyle(theme));
        if (stage != null && stage.getScene() != null) {
            dialog.initOwner(stage);
        }
        return dialog;
    }

    private void addIcons(Stage s) {
        for (int size : ICON_SIZES) {
            InputStream in = getClass().getResourceAsStream("/icons/aegislens-" + size + ".png");
            if (in != null) {
                s.getIcons().add(new Image(in));
            }
        }
    }

    private ImageView logo(int size) {
        int source = size <= 16 ? 16 : size <= 32 ? 32 : size <= 64 ? 64 : 128;
        ImageView view = new ImageView(new Image(getClass().getResourceAsStream("/icons/aegislens-" + source + ".png"),
                size, size, true, true));
        view.setSmooth(true);
        return view;
    }

    /** File > Back up database...: a consistent copy (VACUUM INTO) in a folder the user picks. */
    private void backupDatabase() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Folder for the database backup");
        File dir = chooser.showDialog(stage);
        if (dir != null) {
            UiTasks.run("backup", () -> new BackupService(coordinator.database()).backup(dir.toPath(), LocalDate.now()),
                    path -> styled(new Alert(Alert.AlertType.INFORMATION, "Backup written: " + path)).show(),
                    e -> styled(new Alert(Alert.AlertType.ERROR, "Backup failed: " + e.getMessage())).show());
        }
    }

}
