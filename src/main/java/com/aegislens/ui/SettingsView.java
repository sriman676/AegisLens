package com.aegislens.ui;

import com.aegislens.app.AllowList;
import com.aegislens.app.Branding;
import com.aegislens.app.ConfigFileWriter;
import com.aegislens.app.ScanCoordinator;
import com.aegislens.db.RetentionJob;
import com.aegislens.db.RuleDef;
import com.aegislens.db.RuleRepository;
import com.aegislens.net.NetworkSettings;
import javafx.collections.FXCollections;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ColorPicker;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Spinner;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.ComboBoxTableCell;
import javafx.scene.control.cell.TextFieldTableCell;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.stage.FileChooser;

import java.io.File;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalInt;

/**
 * The Settings view. Applied at once: the allow-list (trusted IPs, ranges and user:names), rule on/off and thresholds,
 * and retention. Saved, then applied by "Restart now": the proxy and the start-up options (written to aegislens.properties
 * only after the same checks as --check-config). Shown read-only: the data folder and the start-up options from
 * aegislens.properties (edit that file and restart). API keys are never shown or stored here; they stay in environment
 * variables.
 */
public final class SettingsView {

    private static final String YES = "on";
    private static final String NO = "off";

    private final ScanCoordinator coordinator;
    private final RuleRepository rules;
    private final TextArea allowList = new TextArea();
    private final TableView<RuleDef> ruleTable = new TableView<>();
    private final TextField findingDays = new TextField();
    private final TextField auditDays = new TextField();
    private final TextField proxyHost = new TextField();
    private final TextField proxyPort = new TextField();
    private final CheckBox systemProxy = new CheckBox("Use the system's proxy settings");
    private final CheckBox criticalNotice = new CheckBox("Show a notice for new CRITICAL findings (off = do not disturb)");
    private final Label message = new Label();
    private final TableView<SystemPresenter.Option> startup = new TableView<>();
    private final Map<String, String> pendingStartup = new LinkedHashMap<>();
    private final HBox restartBar = new HBox(12);
    private final ScrollPane root;

    /** What the window does for Settings: restart its services, or re-apply the look after a change. */
    public interface Host {
        void restart();

        void appearanceChanged();
    }

    private final Host host;
    private final ColorPicker accent = new ColorPicker();
    private final Spinner<Integer> fontSize = new Spinner<>(Appearance.MIN_FONT, Appearance.MAX_FONT, Appearance.DEFAULT_FONT);
    private final TextField orgName = new TextField();
    private boolean ownAccent;

    public SettingsView(ScanCoordinator coordinator, Host host) {
        this.coordinator = coordinator;
        this.host = host;
        this.rules = new RuleRepository(coordinator.database());
        VBox header = Ui.header("Settings", "API keys are never entered here: they stay in environment variables (see .env.example).");
        message.getStyleClass().add("card-sub");
        message.setWrapText(true);
        message.managedProperty().bind(message.textProperty().isNotEmpty());
        Label waiting = new Label("Saved changes that apply after a restart are waiting.");
        waiting.getStyleClass().add("card-sub");
        restartBar.getChildren().setAll(waiting, Ui.button("Restart now", "primary-button", host::restart));
        restartBar.setAlignment(Pos.CENTER_LEFT);
        showRestartBar(false);
        VBox content = new VBox(16, header, message, restartBar, appearancePanel(), allowListPanel(), rulesPanel(), retentionPanel(),
                proxyPanel(), siemPanel(), startupPanel());
        content.getStyleClass().add("dashboard");
        root = new ScrollPane(content);
        root.setFitToWidth(true);
        root.getStyleClass().add("page-scroll");
        load();
    }

    public Node node() {
        return root;
    }

    // ---------------------------------------------------------------- panels

    /** Accent colour (ColorPicker), base font size (Spinner), organisation name and logo; applied at once. */
    private VBox appearancePanel() {
        Appearance now = Appearance.of(coordinator.setting(Appearance.ACCENT_SETTING, null),
                coordinator.setting(Appearance.FONT_SETTING, null));
        ownAccent = now.accent() != null;
        if (ownAccent) {
            accent.setValue(Color.web(now.accent()));
        }
        accent.setOnAction(e -> ownAccent = true);
        fontSize.getValueFactory().setValue(now.fontSize());
        fontSize.setPrefWidth(80);
        orgName.setText(coordinator.setting(Branding.NAME_SETTING, ""));
        criticalNotice.setSelected(!"false".equals(coordinator.setting(CriticalToast.SETTING, "true")));
        orgName.setPromptText("Your organisation (shown on reports and in About)");
        orgName.setPrefColumnCount(28);
        HBox look = new HBox(10, new Label("Accent colour"), accent,
                Ui.button("Use the design's colour", "secondary-button", () -> ownAccent = false),
                new Label("Text size"), fontSize, new Label("px"));
        HBox brand = new HBox(10, new Label("Name"), orgName,
                Ui.button("Choose logo (PNG/JPEG)...", "secondary-button", this::chooseLogo),
                Ui.button("Remove logo", "secondary-button", this::removeLogo));
        look.setAlignment(Pos.CENTER_LEFT);
        brand.setAlignment(Pos.CENTER_LEFT);
        return Ui.panel(Ui.section("APPEARANCE AND BRANDING (APPLIED AT ONCE; HIGH CONTRAST KEEPS ITS COLOURS)"), look, brand,
                criticalNotice,
                Ui.button("Save appearance", "primary-button", this::saveAppearance));
    }

    private void saveAppearance() {
        Color c = accent.getValue();
        String hex = String.format("#%02X%02X%02X", Math.round(c.getRed() * 255), Math.round(c.getGreen() * 255),
                Math.round(c.getBlue() * 255));
        coordinator.saveSetting(Appearance.ACCENT_SETTING, ownAccent ? hex : "");
        coordinator.saveSetting(Appearance.FONT_SETTING, String.valueOf(fontSize.getValue()));
        coordinator.saveSetting(Branding.NAME_SETTING, Branding.cleanName(orgName.getText()));
        coordinator.saveSetting(CriticalToast.SETTING, String.valueOf(criticalNotice.isSelected()));
        host.appearanceChanged();
        message.setText("Appearance saved.");
    }

    private void chooseLogo() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Logo for reports and About (PNG or JPEG, at most 512 KB)");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Images", "*.png", "*.jpg", "*.jpeg"));
        File file = chooser.showOpenDialog(root.getScene() == null ? null : root.getScene().getWindow());
        if (file != null) {
            UiTasks.run("logo", () -> Branding.storeLogo(coordinator.config().paths().dataDir(), file.toPath()),
                    problem -> message.setText(problem.orElse("Logo saved; it appears on the next report and in About.")),
                    this::fail);
        }
    }

    private void removeLogo() {
        UiTasks.run("logo-remove", () -> {
            Branding.removeLogo(coordinator.config().paths().dataDir());
            return null;
        }, done -> message.setText("Logo removed."), this::fail);
    }

    private VBox allowListPanel() {
        allowList.setPrefRowCount(3);
        allowList.setWrapText(true);
        allowList.setPromptText("One per line or comma separated: 192.168.1.0/24, 2001:db8::1, user:backup");
        return Ui.panel(Ui.section("ALLOW-LIST (FINDINGS FOR THESE ARE DROPPED · APPLIED AT ONCE)"), allowList,
                Ui.button("Save allow-list", "primary-button", this::saveAllowList));
    }

    private VBox rulesPanel() {
        ruleTable.getColumns().add(Ui.column("Rule", 80, RuleDef::id));
        ruleTable.getColumns().add(Ui.column("Name", 260, RuleDef::name));
        ruleTable.getColumns().add(Ui.column("Module", 90, RuleDef::module));
        TableColumn<RuleDef, String> enabled = Ui.column("Enabled (double-click)", 140, r -> r.enabled() ? YES : NO);
        enabled.setCellFactory(ComboBoxTableCell.forTableColumn(FXCollections.observableArrayList(YES, NO)));
        enabled.setOnEditCommit(e -> saveRule(() -> rules.setEnabled(e.getRowValue().id(), YES.equals(e.getNewValue()))));
        TableColumn<RuleDef, String> threshold = Ui.column("Threshold (double-click)", 160,
                r -> r.threshold() == null ? "" : String.valueOf(r.threshold()));
        threshold.setCellFactory(TextFieldTableCell.forTableColumn());
        threshold.setOnEditCommit(e -> {
            OptionalDouble t = SystemPresenter.threshold(e.getNewValue());
            if (t.isEmpty()) {
                message.setText("A threshold must be a positive number.");
                ruleTable.refresh();
                return;
            }
            saveRule(() -> rules.setThreshold(e.getRowValue().id(), t.getAsDouble()));
        });
        ruleTable.getColumns().add(enabled);
        ruleTable.getColumns().add(threshold);
        ruleTable.setEditable(true);
        ruleTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        ruleTable.setPrefHeight(320);
        return Ui.panel(Ui.section("DETECTION RULES (APPLIED AT ONCE; DEFAULTS FROM the README rule table)"), ruleTable);
    }

    private VBox retentionPanel() {
        findingDays.setPrefColumnCount(5);
        auditDays.setPrefColumnCount(5);
        HBox row = new HBox(10, new Label("Delete resolved / false-positive findings after"), findingDays,
                new Label("days; audit rows after"), auditDays, new Label("days"),
                Ui.button("Save", "primary-button", this::saveRetention),
                Ui.button("Clean up now", "secondary-button", this::cleanUpNow));
        row.setAlignment(Pos.CENTER_LEFT);
        return Ui.panel(Ui.section("RETENTION (OPEN FINDINGS ARE NEVER DELETED)"), row);
    }

    private VBox proxyPanel() {
        proxyHost.setPromptText("proxy.example.org (blank: no fixed proxy)");
        proxyPort.setPromptText("3128");
        proxyPort.setPrefColumnCount(6);
        HBox row = new HBox(10, new Label("Host"), proxyHost, new Label("Port"), proxyPort, systemProxy,
                Ui.button("Save", "primary-button", this::saveProxy));
        row.setAlignment(Pos.CENTER_LEFT);
        return Ui.panel(Ui.section("NETWORK PROXY (APPLIED AT THE NEXT START)"), row);
    }

    /** Where findings are forwarded (siem.* start-up options) with a test event to check the connection. */
    private VBox siemPanel() {
        Label status = new Label();
        status.getStyleClass().add("card-sub");
        status.setWrapText(true);
        Runnable show = () -> status.setText(coordinator.siem().map(f -> SystemPresenter.siemText(f.settings().describe(),
                f.sentCount(), f.failedCount(), f.droppedCount(), f.lastError() == null ? null : SafeText.shorten(f.lastError())))
                .orElse(SystemPresenter.siemText(null, 0, 0, 0, null)));
        show.run();
        HBox row = new HBox(10, Ui.button("Send test event", "primary-button", () -> {
            if (coordinator.siem().map(f -> f.sendTest(java.time.Clock.systemUTC())).orElse(false)) {
                message.setText("Test event TEST-000 queued; search your SIEM for it.");
            }
            javafx.animation.PauseTransition later = new javafx.animation.PauseTransition(javafx.util.Duration.seconds(3));
            later.setOnFinished(e -> show.run());
            later.play();
        }), Ui.button("Refresh status", "secondary-button", show));
        row.setAlignment(Pos.CENTER_LEFT);
        return Ui.panel(Ui.section("SIEM FORWARDING (SYSLOG CEF/JSON OVER UDP, TCP OR TLS; JSON-LINES FILE)"), status, row);
    }

    private VBox startupPanel() {
        startup.getColumns().add(Ui.column("Option", 220, SystemPresenter.Option::key));
        TableColumn<SystemPresenter.Option, String> inFile = Ui.column("In the file (double-click; blank = default)", 300,
                o -> SafeText.shorten(o.inFile()));
        inFile.setCellFactory(TextFieldTableCell.forTableColumn());
        inFile.setOnEditCommit(e -> {
            SystemPresenter.Option o = e.getRowValue();
            String value = e.getNewValue().strip();
            pendingStartup.put(o.key(), value);
            startup.getItems().set(e.getTablePosition().getRow(), new SystemPresenter.Option(o.key(), value, o.inEffect()));
            message.setText(pendingStartup.size() + " start-up option(s) changed; press Save start-up options.");
        });
        startup.getColumns().add(inFile);
        startup.getColumns().add(Ui.column("In effect now", 300, o -> SafeText.shorten(o.inEffect())));
        startup.setEditable(true);
        startup.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        startup.setPrefHeight(320);
        Label where = new Label("Data folder: " + coordinator.config().paths().dataDir()
                + "\nFile: " + coordinator.config().paths().configFile()
                + "  (a command-line --key=value or AEGISLENS_* variable wins over the file)");
        where.setWrapText(true);
        where.getStyleClass().add("card-sub");
        return Ui.panel(Ui.section("START-UP OPTIONS (SAVED TO THE FILE, APPLIED BY RESTART NOW)"), where, startup,
                Ui.button("Save start-up options", "primary-button", this::saveStartup));
    }

    private void showRestartBar(boolean visible) {
        restartBar.setVisible(visible);
        restartBar.setManaged(visible);
    }

    /** Checks and writes the edited options; the file is only replaced if every value is valid. */
    private void saveStartup() {
        if (pendingStartup.isEmpty()) {
            message.setText("Nothing changed: double-click a value in the start-up table first.");
            return;
        }
        Map<String, String> changes = new LinkedHashMap<>(pendingStartup);
        UiTasks.run("startup", () -> ConfigFileWriter.update(coordinator.config().paths().configFile(), changes,
                coordinator.config().paths().dataDir()), problems -> {
            if (problems.isEmpty()) {
                pendingStartup.clear();
                message.setText("Start-up options saved. Press Restart now to use them.");
                showRestartBar(true);
            } else {
                message.setText("Not saved: " + SafeText.shorten(String.join("; ", problems)));
            }
        }, this::fail);
    }

    // ---------------------------------------------------------------- load and save

    private void load() {
        UiTasks.run("settings", () -> new Values(coordinator.setting(AllowList.SETTING, ""), rules.findAll(),
                coordinator.setting(RetentionJob.FINDING_DAYS_SETTING, String.valueOf(RetentionJob.DEFAULT_FINDING_DAYS)),
                coordinator.setting(RetentionJob.AUDIT_DAYS_SETTING, String.valueOf(RetentionJob.DEFAULT_AUDIT_DAYS)),
                coordinator.setting(NetworkSettings.PROXY_HOST, ""), coordinator.setting(NetworkSettings.PROXY_PORT, ""),
                Boolean.parseBoolean(coordinator.setting(NetworkSettings.SYSTEM_PROXIES, "false")),
                SystemPresenter.startupOptions(coordinator.config(), ConfigFileWriter.read(coordinator.config().paths().configFile()))), v -> {
            allowList.setText(v.allowList().replace(", ", "\n"));
            ruleTable.getItems().setAll(v.rules());
            findingDays.setText(v.findingDays());
            auditDays.setText(v.auditDays());
            proxyHost.setText(v.proxyHost());
            proxyPort.setText(v.proxyPort());
            systemProxy.setSelected(v.systemProxy());
            startup.getItems().setAll(v.startup());
        }, this::fail);
    }

    private record Values(String allowList, List<RuleDef> rules, String findingDays, String auditDays, String proxyHost,
                          String proxyPort, boolean systemProxy, List<SystemPresenter.Option> startup) {
    }

    private void saveAllowList() {
        String text = SystemPresenter.normalizeAllowList(allowList.getText());
        List<String> bad = AllowList.invalidEntries(text);
        if (!bad.isEmpty()) {
            message.setText("Not saved. These are not an IP, a CIDR range or user:name: " + SafeText.shorten(String.join(", ", bad)));
            return;
        }
        UiTasks.run("allowlist", () -> {
            coordinator.saveSetting(AllowList.SETTING, text);
            coordinator.reloadAllowList();
            return text;
        }, t -> {
            allowList.setText(t.replace(", ", "\n"));
            message.setText("Allow-list saved and applied.");
        }, this::fail);
    }

    @FunctionalInterface
    private interface RuleChange {
        boolean apply() throws Exception;
    }

    private void saveRule(RuleChange change) {
        UiTasks.run("rule", () -> {
            boolean changed = change.apply();
            coordinator.reloadRules();
            return changed;
        }, changed -> {
            message.setText(changed ? "Rule saved and applied now (log counters restart from zero)." : "Rule not found.");
            load();
        }, this::fail);
    }

    private void saveRetention() {
        OptionalInt f = SystemPresenter.days(findingDays.getText());
        OptionalInt a = SystemPresenter.days(auditDays.getText());
        if (f.isEmpty() || a.isEmpty()) {
            message.setText("Days must be whole numbers from " + SystemPresenter.MIN_DAYS + " to " + SystemPresenter.MAX_DAYS + ".");
            return;
        }
        coordinator.saveSetting(RetentionJob.FINDING_DAYS_SETTING, String.valueOf(f.getAsInt()));
        coordinator.saveSetting(RetentionJob.AUDIT_DAYS_SETTING, String.valueOf(a.getAsInt()));
        message.setText("Retention saved; the daily clean-up uses it.");
    }

    private void cleanUpNow() {
        UiTasks.run("retention", () -> new RetentionJob(coordinator.database()).runOnce(Instant.now()), r -> message.setText(
                "Clean-up done: " + r.findingsDeleted() + " findings, " + r.sessionsDeleted() + " empty sessions, "
                        + r.auditDeleted() + " audit rows deleted" + (r.vacuumed() ? "; file compacted." : ".")), this::fail);
    }

    private void saveProxy() {
        Optional<String> problem = SystemPresenter.proxyProblem(proxyHost.getText(), proxyPort.getText());
        if (problem.isPresent()) {
            message.setText(problem.get());
            return;
        }
        coordinator.saveSetting(NetworkSettings.PROXY_HOST, proxyHost.getText().strip());
        coordinator.saveSetting(NetworkSettings.PROXY_PORT, proxyPort.getText().strip());
        coordinator.saveSetting(NetworkSettings.SYSTEM_PROXIES, String.valueOf(systemProxy.isSelected()));
        message.setText("Proxy saved; it is used after a restart.");
        showRestartBar(true);
    }

    private void fail(Exception e) {
        message.setText("Failed: " + SafeText.shorten(e.getMessage()));
    }
}
