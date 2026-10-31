package com.aegislens.ui;

import com.aegislens.app.AllowList;
import com.aegislens.app.OwnIntel;
import com.aegislens.app.ScanCoordinator;
import com.aegislens.db.BlockedIp;
import com.aegislens.db.BlockedIpRepository;
import com.aegislens.db.IocRepository;
import com.aegislens.intel.FeedCatalog;
import com.aegislens.intel.FeedUpdater;
import com.aegislens.response.BlocklistExporter;
import javafx.collections.FXCollections;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.Window;

import java.io.File;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The Threat Intel view: one row per feed (state, entries, last update, error, attribution as the licences require),
 * "Update now", the number of stored indicators per kind, and whether VirusTotal lookups are on (the key is never shown).
 */
public final class IntelView {

    private final ScanCoordinator coordinator;
    private final LatestOnly loads = new LatestOnly();
    private final IocRepository iocs;
    private final BlockedIpRepository blocked;
    private final Window owner;
    private final TableView<BlockedIp> blocks = new TableView<>();
    private final TableView<FeedUpdater.Status> feeds = new TableView<>();
    private final Label iocLine = new Label();
    private final Label vtLine = new Label();
    private final Label message = new Label();
    private final Button update = Ui.button("Update now", "primary-button", this::updateNow);
    private final OwnIntel own;
    private final TableView<IocRepository.IocEntry> ownTable = new TableView<>();
    private final HBox restartBar = new HBox(12);
    private final ScrollPane root;

    /** restarter is "Restart now": feed changes are read when the services start. */
    public IntelView(ScanCoordinator coordinator, Window owner, Runnable restarter) {
        this.coordinator = coordinator;
        this.owner = owner;
        this.own = new OwnIntel(coordinator);
        this.iocs = new IocRepository(coordinator.database());
        this.blocked = new BlockedIpRepository(coordinator.database());
        VBox header = Ui.header("Threat intelligence", "Free public block lists, refreshed automatically and kept for offline use. An update is a plain download; nothing is sent about you.");

        feeds.getColumns().add(Ui.column("Feed", 140, FeedUpdater.Status::feed));
        feeds.getColumns().add(Ui.column("State", 70, SystemPresenter::feedState));
        feeds.getColumns().add(Ui.column("Entries", 80, s -> String.valueOf(s.entries())));
        feeds.getColumns().add(Ui.column("Updated", 100, s -> SystemPresenter.feedAge(s, Instant.now())));
        feeds.getColumns().add(Ui.column("Last error", 200, s -> SafeText.shorten(s.lastError())));
        feeds.getColumns().add(Ui.column("Source and licence", 320, s -> SafeText.shorten(s.attribution())));
        feeds.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        feeds.setPrefHeight(170);
        feeds.setPlaceholder(new Label("No feeds configured (see feeds.properties in the data folder)."));
        iocLine.getStyleClass().add("card-sub");
        vtLine.getStyleClass().add("card-sub");
        vtLine.setWrapText(true);
        message.getStyleClass().add("card-sub");
        message.setWrapText(true);

        Label waiting = new Label("Feed changes are used after a restart.");
        waiting.getStyleClass().add("card-sub");
        restartBar.getChildren().setAll(waiting, Ui.button("Restart now", "primary-button", restarter));
        restartBar.setAlignment(Pos.CENTER_LEFT);
        restartBar.setVisible(false);
        restartBar.managedProperty().bind(restartBar.visibleProperty());
        VBox panel = Ui.panel(new HBox(12, Ui.section("FEEDS"), update,
                        Ui.button("Turn selected on/off", "secondary-button", this::toggleFeed),
                        Ui.button("Remove own feed", "secondary-button", this::removeFeed)),
                feeds, iocLine, vtLine, message, restartBar, feedForm());

        VBox content = new VBox(18, header, panel, ownPanel(), blocksPanel());
        content.getStyleClass().add("dashboard");
        root = new ScrollPane(content);
        root.setFitToWidth(true);
        root.getStyleClass().add("page-scroll");
        refresh();
    }

    public Node node() {
        return root;
    }

    public void refresh() {
        loads.run("intel", () -> new Data(coordinator.feedStatus(), iocs.countByKind(), blocked.findAll(), own.list()), d -> {
            feeds.getItems().setAll(d.feeds());
            blocks.getItems().setAll(d.blocks());
            ownTable.getItems().setAll(d.own());
            iocLine.setText(SystemPresenter.iocLine(d.byKind()));
            vtLine.setText(SystemPresenter.virusTotalText(coordinator.virusTotalEnabled(), coordinator.virusTotalQueued()));
        }, e -> message.setText("Failed: " + SafeText.shorten(e.getMessage())));
    }

    private record Data(List<FeedUpdater.Status> feeds, Map<String, Integer> byKind, List<BlockedIp> blocks,
                        List<IocRepository.IocEntry> own) {
    }

    // ---------------------------------------------------------------- your own feeds

    /** Name, https address, format and kind of a new feed; checked like the bundled ones before it is saved. */
    private HBox feedForm() {
        TextField name = new TextField();
        name.setPromptText("name (a-z, 0-9, -)");
        name.setPrefColumnCount(10);
        TextField url = new TextField();
        url.setPromptText("https://... (a list you trust)");
        HBox.setHgrow(url, Priority.ALWAYS);
        ComboBox<String> format = new ComboBox<>(FXCollections.observableArrayList(FeedCatalog.FORMATS.stream().sorted().toList()));
        format.setValue("ip-lines");
        ComboBox<String> kind = new ComboBox<>(FXCollections.observableArrayList(FeedCatalog.KINDS.stream().sorted().toList()));
        kind.setValue("IP");
        TextField credit = new TextField();
        credit.setPromptText("source / licence");
        credit.setPrefColumnCount(12);
        Button add = Ui.button("Add feed", "secondary-button", () -> UiTasks.run("feed-add", () -> {
            OwnIntel.addFeed(dataDir(), name.getText().strip(), url.getText(), format.getValue(), kind.getValue(), credit.getText());
            return name.getText().strip();
        }, n -> feedChanged("Feed " + n + " saved."), this::fail));
        HBox row = new HBox(8, Ui.section("ADD A FEED"), name, url, format, kind, credit, add);
        row.setAlignment(Pos.CENTER_LEFT);
        return row;
    }

    private void toggleFeed() {
        FeedUpdater.Status s = feeds.getSelectionModel().getSelectedItem();
        if (s != null) {
            UiTasks.run("feed-toggle", () -> {
                OwnIntel.setFeedEnabled(dataDir(), s.feed(), !s.enabled());
                return s;
            }, x -> feedChanged(s.feed() + (s.enabled() ? " turned off." : " turned on.")), this::fail);
        }
    }

    private void removeFeed() {
        FeedUpdater.Status s = feeds.getSelectionModel().getSelectedItem();
        if (s != null) {
            UiTasks.run("feed-remove", () -> OwnIntel.removeFeed(dataDir(), s.feed()), removed -> {
                if (removed) {
                    feedChanged(s.feed() + " removed.");
                } else {
                    message.setText(s.feed() + " is a bundled feed: it can only be turned off.");
                }
            }, this::fail);
        }
    }

    private void feedChanged(String text) {
        message.setText(text + " Press Restart now to use it.");
        restartBar.setVisible(true);
    }

    private Path dataDir() {
        return coordinator.config().paths().dataDir();
    }

    // ---------------------------------------------------------------- your own indicators

    /** Add an IP, range, SHA-256, domain or URL you want watched; IPs and ranges apply to live detection at once. */
    private VBox ownPanel() {
        ComboBox<String> kind = new ComboBox<>(FXCollections.observableArrayList(OwnIntel.KINDS));
        kind.setValue("IP");
        TextField value = new TextField();
        value.setPromptText("203.0.113.9, 198.51.100.0/24, a SHA-256, bad-site.example or https://bad-site.example/login");
        HBox.setHgrow(value, Priority.ALWAYS);
        CheckBox c2 = new CheckBox("botnet controller (C2)");
        TextField note = new TextField();
        note.setPromptText("why (optional)");
        note.setPrefColumnCount(14);
        Button add = Ui.button("Add", "primary-button", () -> UiTasks.run("ioc-add",
                () -> own.add(kind.getValue(), value.getText(), c2.isSelected(), note.getText()), text -> {
                    message.setText(text);
                    value.clear();
                    refresh();
                }, this::fail));
        ownTable.getColumns().add(Ui.column("Kind", 70, IocRepository.IocEntry::kind));
        ownTable.getColumns().add(Ui.column("Value", 300, e -> SafeText.shorten(e.value())));
        ownTable.getColumns().add(Ui.column("List", 90, e -> OwnIntel.C2_SOURCE.equals(e.source()) ? "C2" : "watch/block"));
        ownTable.getColumns().add(Ui.column("Note", 240, e -> SafeText.shorten(e.note())));
        ownTable.getColumns().add(Ui.column("Added", 120, e -> SafeText.shorten(e.addedAt())));
        ownTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        ownTable.setPlaceholder(new Label("Nothing added yet."));
        ownTable.setPrefHeight(180);
        Button remove = Ui.button("Remove selected", "secondary-button", () -> {
            IocRepository.IocEntry e = ownTable.getSelectionModel().getSelectedItem();
            if (e != null) {
                UiTasks.run("ioc-remove", () -> own.remove(e.id()), removed -> refresh(), this::fail);
            }
        });
        HBox form = new HBox(8, kind, value, c2, note, add);
        form.setAlignment(Pos.CENTER_LEFT);
        return Ui.panel(new HBox(12, Ui.section("YOUR OWN INDICATORS (IPS AND RANGES APPLY AT ONCE; SHA-256 ON THE NEXT SCAN)"), remove),
                form, ownTable);
    }

    private void fail(Exception e) {
        message.setText("Not done: " + SafeText.shorten(e.getMessage()));
    }

    /** Addresses recorded with "Record block" (Findings view or console); exported as files, never applied. */
    private VBox blocksPanel() {
        blocks.getColumns().add(Ui.column("Address", 220, BlockedIp::ip));
        blocks.getColumns().add(Ui.column("Reason", 420, b -> SafeText.shorten(b.reason())));
        blocks.getColumns().add(Ui.column("Recorded", 180, b -> SafeText.time(b.blockedAt().toString())));
        blocks.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        blocks.setPlaceholder(new Label("No blocks recorded. Use Record block in the Findings view."));
        blocks.setPrefHeight(200);
        Button unblock = Ui.button("Unblock selected", "secondary-button", this::unblock);
        Button export = Ui.button("Export blocklist + firewall commands...", "primary-button", this::exportBlocklist);
        return Ui.panel(new HBox(12, Ui.section("RECORDED BLOCKS (AEGISLENS NEVER CHANGES YOUR FIREWALL)"), export, unblock), blocks);
    }

    private void unblock() {
        BlockedIp b = blocks.getSelectionModel().getSelectedItem();
        if (b != null) {
            UiTasks.run("unblock", () -> blocked.unblock(b.ip()), done -> {
                message.setText("Unblocked " + b.ip());
                refresh();
            }, e -> message.setText("Failed: " + SafeText.shorten(e.getMessage())));
        }
    }

    /** File > Export blocklist… also lands here. Writes blocklist.txt and command files to review; nothing is run. */
    public void exportBlocklist() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Folder for the blocklist files");
        File dir = chooser.showDialog(owner);
        if (dir == null) {
            return;
        }
        UiTasks.run("blocklist", () -> new BlocklistExporter(AllowList.parse(coordinator.setting(AllowList.SETTING, "")))
                .export(blocked.findAll(), dir.toPath(), Instant.now()), r -> message.setText("Wrote " + r.written()
                + " address(es) to " + BlocklistExporter.FILES.size() + " files in " + dir.getName() + " (review before use)"
                + (r.skipped().isEmpty() ? "." : "; left out: " + SafeText.shorten(r.skipped().toString()))),
                e -> message.setText("Export failed: " + SafeText.shorten(e.getMessage())));
    }

    /** "Update now", also Tools > Update threat feeds now. */
    public void updateNow() {
        update.setDisable(true);
        message.setText("Downloading the enabled feeds…");
        UiTasks.await("intel-update", coordinator.updateFeedsNow(), results -> {
            update.setDisable(false);
            StringBuilder sb = new StringBuilder();
            for (FeedUpdater.Result r : results) {
                sb.append(r.feed()).append(": ").append(r.outcome()).append(" (").append(SafeText.shorten(r.message())).append(")   ");
            }
            message.setText(results.isEmpty() ? "No feeds are enabled." : sb.toString().strip());
            refresh();
        }, e -> {
            update.setDisable(false);
            message.setText("Update failed: " + SafeText.shorten(e.getMessage()));
        });
    }
}
