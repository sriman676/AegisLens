package com.aegislens.ui;

import com.aegislens.app.ScanCoordinator;
import com.aegislens.core.Finding;
import com.aegislens.intrusion.LogType;
import com.aegislens.intrusion.MonitorManager.SourceStatus;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Window;
import javafx.util.Duration;
import javafx.util.StringConverter;

import java.io.File;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;

/**
 * The Intrusion view: watch a log live or replay it once. A ComboBox picks the kind of log, a TextField (with Browse)
 * holds the path, RadioButtons choose Live or Replay, and Start runs it through ScanCoordinator. The table shows every
 * live source with its counters (refreshed every 2 s); the list shows the latest intrusion findings with a filter box.
 */
public final class IntrusionView {

    private static final Duration POLL = Duration.seconds(2);

    private final ScanCoordinator coordinator;
    private final Window owner;
    private final ComboBox<LogType> type = new ComboBox<>(FXCollections.observableArrayList(LogType.values()));
    private final TextField path = new TextField();
    private final ToggleGroup mode = new ToggleGroup();
    private final RadioButton live = new RadioButton("Live (keep watching)");
    private final RadioButton replay = new RadioButton("Replay once");
    private final CheckBox fromStart = new CheckBox("Read the lines already in the file");
    private final TableView<SourceStatus> sources = new TableView<>();
    private final ObservableList<Finding> recent = FXCollections.observableArrayList();
    private final FilteredList<Finding> shown = new FilteredList<>(recent);
    private final Label message = new Label();
    private final Label summary = new Label();
    private final Timeline poll = new Timeline(new KeyFrame(POLL, e -> refresh()));
    private final VBox root;

    public IntrusionView(ScanCoordinator coordinator, Window owner) {
        this.coordinator = coordinator;
        this.owner = owner;
        VBox header = Ui.header("Intrusion", "Watch SSH and web-server logs live, or replay any supported log once. Lines are only read.");

        HBox body = new HBox(16, form(), recentPanel());
        VBox.setVgrow(body, Priority.ALWAYS);
        message.getStyleClass().add("card-sub");
        message.setWrapText(true);
        root = new VBox(18, header, body, message);
        root.getStyleClass().add("dashboard");
        poll.setCycleCount(Timeline.INDEFINITE);
        poll.play();
        refresh();
    }

    public Node node() {
        return root;
    }

    /** Called on the persister thread for every saved finding; only intrusion findings are kept. */
    public void onFinding(Finding f) {
        if (IntrusionPresenter.isIntrusion(f)) {
            Platform.runLater(() -> {
                recent.add(0, f);
                if (recent.size() > IntrusionPresenter.RECENT) {
                    recent.remove(IntrusionPresenter.RECENT, recent.size());
                }
            });
        }
    }

    public void stop() {
        poll.stop();
    }

    /** Scan > Replay log... (Ctrl+R): choose a file, switch to Replay and start. */
    public void chooseAndReplay() {
        if (browse()) {
            replay.setSelected(true);
            start();
        }
    }

    // ---------------------------------------------------------------- layout

    private VBox form() {
        type.setValue(LogType.SSH);
        type.setConverter(new StringConverter<>() {
            @Override
            public String toString(LogType t) {
                return t == null ? "" : t.label();
            }

            @Override
            public LogType fromString(String s) {
                return null;
            }
        });
        path.setPromptText("Path of the log file, e.g. /var/log/auth.log");
        HBox.setHgrow(path, Priority.ALWAYS);
        Button browse = Ui.button("Browse...", "secondary-button", () -> browse());
        live.setToggleGroup(mode);
        replay.setToggleGroup(mode);
        live.setSelected(true);
        fromStart.disableProperty().bind(replay.selectedProperty());       // a replay always reads the whole file
        Button start = Ui.button("Start", "primary-button", this::start);
        Button stopSource = Ui.button("Stop selected source", "secondary-button", this::stopSelected);

        sources.getColumns().add(Ui.column("Source", 260, s -> SafeText.shorten(s.name())));
        sources.getColumns().add(Ui.column("State", 100, SourceStatus::state));
        sources.getColumns().add(Ui.column("Lines", 70, s -> String.valueOf(s.lines())));
        sources.getColumns().add(Ui.column("Events", 70, s -> String.valueOf(s.events())));
        sources.getColumns().add(Ui.column("Findings", 70, s -> String.valueOf(s.findings())));
        sources.getColumns().add(Ui.column("Skipped", 70, s -> String.valueOf(s.malformed() + s.dropped())));
        sources.getColumns().add(Ui.column("Last line", 100, s -> IntrusionPresenter.ago(s.lastActivity(), Instant.now())));
        sources.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        sources.setPlaceholder(new Label("Nothing is watched yet. Pick a log above and press Start."));
        summary.getStyleClass().add("card-sub");

        HBox row1 = new HBox(10, new Label("Kind"), type, path, browse);
        HBox row2 = new HBox(16, live, replay, fromStart, start);
        row1.setAlignment(Pos.CENTER_LEFT);
        row2.setAlignment(Pos.CENTER_LEFT);
        VBox box = Ui.panel(Ui.section("ADD A SOURCE"), row1, row2, Ui.section("LIVE SOURCES"), sources,
                new HBox(12, stopSource, summary));
        VBox.setVgrow(sources, Priority.ALWAYS);
        HBox.setHgrow(box, Priority.ALWAYS);
        return box;
    }

    private VBox recentPanel() {
        TextField filter = new TextField();
        filter.setPromptText("Filter: rule, IP or text");
        filter.textProperty().addListener((o, a, text) -> shown.setPredicate(f -> IntrusionPresenter.matches(f, text)));
        ListView<Finding> list = new ListView<>(shown);
        list.setCellFactory(l -> new ListCell<>() {
            @Override
            protected void updateItem(Finding f, boolean empty) {
                super.updateItem(f, empty);
                setText(empty || f == null ? null : SafeText.shorten(AiPresenter.findingLine(f)));
            }
        });
        list.setPlaceholder(new Label("Intrusion findings appear here as they are detected."));
        VBox box = Ui.panel(Ui.section("LATEST " + IntrusionPresenter.RECENT + " INTRUSION FINDINGS"), filter, list);
        VBox.setVgrow(list, Priority.ALWAYS);
        box.setPrefWidth(420);
        box.setMinWidth(340);
        return box;
    }

    // ---------------------------------------------------------------- actions

    /** Returns true if a file was chosen. */
    private boolean browse() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose a log file");
        File f = chooser.showOpenDialog(owner);
        if (f != null) {
            path.setText(f.getAbsolutePath());
            type.setValue(IntrusionPresenter.guessType(f.getName()));
        }
        return f != null;
    }

    private void start() {
        boolean isLive = live.isSelected();
        Optional<String> problem = IntrusionPresenter.problem(path.getText(), type.getValue(), isLive);
        if (problem.isPresent()) {
            message.setText(problem.get());
            return;
        }
        Path file = Path.of(path.getText().strip());
        LogType kind = type.getValue();
        if (isLive) {
            UiTasks.run("monitor-add", () -> {
                coordinator.addMonitorFile(file, kind, fromStart.isSelected());
                return file;
            }, f -> message.setText("Watching " + SafeText.shorten(f.toString())), this::fail);
        } else {
            message.setText("Replaying " + SafeText.shorten(file.getFileName().toString()) + "…");
            UiTasks.await("replay", coordinator.replayLog(file, kind), r -> message.setText(String.format(
                    "Replay of %s: %d lines, %d events, %d findings, %d unreadable lines skipped.",
                    SafeText.shorten(file.getFileName().toString()), r.lines(), r.events(), r.findings(),
                    r.malformed() + r.overlong())), this::fail);
        }
    }

    private void stopSelected() {
        SourceStatus s = sources.getSelectionModel().getSelectedItem();
        if (s == null) {
            message.setText("Select a source in the table first.");
            return;
        }
        UiTasks.run("monitor-remove", () -> coordinator.removeMonitorFile(Path.of(s.name())), removed -> {
            message.setText(removed ? "Stopped " + SafeText.shorten(s.name()) : "The syslog listener is configured in Settings.");
            refresh();
        }, this::fail);
    }

    private void refresh() {
        UiTasks.run("monitor-status", coordinator::monitorStatus, list -> {
            SourceStatus selected = sources.getSelectionModel().getSelectedItem();
            sources.getItems().setAll(list);
            list.stream().filter(s -> selected != null && s.name().equals(selected.name())).findFirst()
                    .ifPresent(s -> sources.getSelectionModel().select(s));
            summary.setText(IntrusionPresenter.summary(list));
        }, this::fail);
    }

    private void fail(Exception e) {
        message.setText("Failed: " + SafeText.shorten(e.getMessage()));
    }
}
