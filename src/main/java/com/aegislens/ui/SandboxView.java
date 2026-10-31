package com.aegislens.ui;

import com.aegislens.app.ScanCoordinator;
import com.aegislens.app.ScanCoordinator.SandboxRun;
import com.aegislens.sandbox.DemoProgram;
import javafx.collections.FXCollections;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Window;
import javafx.util.StringConverter;

import java.io.File;
import java.util.List;
import java.util.concurrent.Future;
import java.util.function.Consumer;

/**
 * The Sandbox view (P9). Demo programs: pick one of the team's own harmless programs (a ComboBox of the DemoProgram
 * enum, so no file can ever be chosen here), run it in the local sandbox and see its output, created files and SBX
 * findings. Container: a button that stays disabled unless AEGISLENS_ENABLE_REAL_SANDBOX=1 and a Docker/Podman engine
 * answer, and that asks for confirmation quoting the safety rules before running a sample.
 */
public final class SandboxView {

    private final ScanCoordinator coordinator;
    private final Window owner;
    private final Consumer<Dialog<?>> styler;
    private final ComboBox<DemoProgram> demo = new ComboBox<>(FXCollections.observableArrayList(DemoProgram.values()));
    private final Label description = new Label();
    private final Label summary = new Label("Pick a demo program and press Run.");
    private final TextArea output = new TextArea();
    private final ListView<String> files = new ListView<>();
    private final ListView<String> findings = new ListView<>();
    private final Label containerState = new Label("Container sandbox: checking…");
    private final Button run = Ui.button("Run demo", "primary-button", this::runDemo);
    private final Button container = Ui.button("Run sample in container...", "danger-button", this::runInContainer);
    private final VBox root;

    public SandboxView(ScanCoordinator coordinator, Window owner, Consumer<Dialog<?>> styler) {
        this.coordinator = coordinator;
        this.owner = owner;
        this.styler = styler;
        VBox header = Ui.header("Sandbox", "Watch what a program does: files it creates, how long it runs, how it ends. "
                + "Here only the team's own harmless demo programs run; unknown files only ever run in a disposable container.");
        demo.setConverter(new StringConverter<>() {
            @Override
            public String toString(DemoProgram d) {
                return d == null ? "" : d.id();
            }

            @Override
            public DemoProgram fromString(String s) {
                return null;
            }
        });
        demo.setOnAction(e -> description.setText(demo.getValue() == null ? "" : demo.getValue().description()));
        demo.setValue(DemoProgram.DROPPER);
        description.setText(DemoProgram.DROPPER.description());
        description.getStyleClass().add("card-sub");
        summary.getStyleClass().add("page-subtitle");
        output.setEditable(false);
        output.setPrefRowCount(8);
        output.getStyleClass().add("answer");
        files.setPlaceholder(new Label("No files created"));
        findings.setPlaceholder(new Label("No findings"));
        files.setPrefHeight(150);
        findings.setPrefHeight(150);
        container.setDisable(true);
        containerState.setWrapText(true);
        containerState.getStyleClass().add("card-sub");

        HBox pick = new HBox(10, new Label("Program"), demo, run, description);
        pick.setAlignment(Pos.CENTER_LEFT);
        VBox fileBox = Ui.panel(Ui.section("FILES IT CREATED"), files);
        VBox findingBox = Ui.panel(Ui.section("FINDINGS (SBX)"), findings);
        HBox.setHgrow(fileBox, Priority.ALWAYS);
        HBox.setHgrow(findingBox, Priority.ALWAYS);
        VBox demos = Ui.panel(Ui.section("DEMO PROGRAMS (LOCAL SANDBOX)"), pick, summary, output, new HBox(16, fileBox, findingBox));
        VBox box = Ui.panel(Ui.section("UNKNOWN FILES (CONTAINER SANDBOX, OFF BY DEFAULT)"), containerState, container);
        root = new VBox(18, header, demos, box);
        root.getStyleClass().add("dashboard");
        UiTasks.run("sandbox-state", coordinator::containerState, state -> {
            containerState.setText(SandboxPresenter.containerText(state));
            container.setDisable(!"ready".equals(state));
        }, e -> containerState.setText(SandboxPresenter.containerText("off")));
    }

    public Node node() {
        return root;
    }

    private void runDemo() {
        DemoProgram d = demo.getValue();
        if (d != null) {
            run.setDisable(true);
            summary.setText("Running " + d.id() + "…");
            show(coordinator.runDemo(d));
        }
    }

    private void runInContainer() {
        Alert a = new Alert(Alert.AlertType.CONFIRMATION, "Run a sample only inside a disposable virtual machine that you can "
                + "throw away afterwards, never on your normal computer. The container has no network, no extra rights, "
                + "a read-only copy of the sample and strict memory, process and time limits (README: Security and safety). Continue?",
                ButtonType.OK, ButtonType.CANCEL);
        a.setHeaderText("Run an unknown file?");
        styler.accept(a);
        ((Button) a.getDialogPane().lookupButton(ButtonType.CANCEL)).setDefaultButton(true);
        ((Button) a.getDialogPane().lookupButton(ButtonType.OK)).setDefaultButton(false);
        if (a.showAndWait().filter(b -> b == ButtonType.OK).isEmpty()) {
            return;
        }
        File file = new FileChooser().showOpenDialog(owner);
        if (file != null) {
            summary.setText("Running " + file.getName() + " in the container…");
            show(coordinator.runInContainer(file.toPath()));
        }
    }

    private void show(Future<SandboxRun> job) {
        UiTasks.await("sandbox", job, r -> {
            run.setDisable(false);
            summary.setText(SandboxPresenter.summary(r.report()));
            output.setText(r.report().output().lines().map(SafeText::shorten).reduce((x, y) -> x + "\n" + y).orElse(""));
            files.getItems().setAll(r.report().createdFiles().stream().map(SafeText::shorten).toList());
            List<String> lines = r.findings().stream().map(f -> f.ruleId() + "  " + f.score() + "  " + SafeText.shorten(f.description())).toList();
            findings.getItems().setAll(lines);
        }, e -> {
            run.setDisable(false);
            summary.setText("Could not run: " + SafeText.shorten(e.getMessage()));
        });
    }
}
