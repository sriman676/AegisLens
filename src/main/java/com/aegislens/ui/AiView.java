package com.aegislens.ui;

import com.aegislens.ai.ExplanationService;
import com.aegislens.app.ScanCoordinator;
import com.aegislens.core.Finding;
import com.aegislens.db.FindingRepository;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.util.StringConverter;

import java.util.Locale;

/**
 * The AI view: pick a finding, pick who explains it (Auto, Claude, Gemini, the local model, SplitShield context or the
 * offline templates) in a ComboBox, and read the answer as plain text with badges (who answered, cached, offline
 * fallback, private values hidden). If it fell back, the reason is shown and "Retry online" tries again. The budget
 * counter shows how many paid cloud calls are left. Work runs off the FX thread.
 */
public final class AiView {

    public static final int RECENT = 200;

    private final ScanCoordinator coordinator;
    private final LatestOnly listLoads = new LatestOnly();
    private final ListView<Finding> findings = new ListView<>();
    private final ComboBox<String> provider = new ComboBox<>();
    private final TextArea answer = new TextArea();
    private final FlowPane badges = new FlowPane(6, 6);
    private final Label error = new Label();
    private final Label budget = new Label();
    private final Button retry = new Button("Retry online");
    private final Button explain = new Button("Explain");
    private final VBox root;

    public AiView(ScanCoordinator coordinator) {
        this.coordinator = coordinator;
        setUpProviderChoice();
        setUpFindingsList();
        setUpAnswerArea();
        VBox header = Ui.header("AI explanations", "Cloud AI gets private values hidden; the local model and SplitShield stay on your machine or network.");
        Region gap = new Region();
        HBox.setHgrow(gap, Priority.ALWAYS);
        HBox head = new HBox(10, header, gap);
        head.setAlignment(Pos.CENTER_LEFT);
        HBox body = new HBox(16, findingsPanel(), explanationPanel());
        VBox.setVgrow(body, Priority.ALWAYS);
        root = new VBox(18, head, body);
        root.getStyleClass().add("dashboard");
        updateBudget();
        loadFindings();
    }

    /** "Auto (best available)", then each registered provider by its readable name. */
    private void setUpProviderChoice() {
        provider.getItems().setAll(AiPresenter.choices(coordinator.explanations().providerNames()));
        provider.setValue(ExplanationService.AUTO);
        provider.setConverter(new StringConverter<>() {
            @Override
            public String toString(String name) {
                return name == null ? "" : AiPresenter.label(name);
            }

            @Override
            public String fromString(String label) {
                return label;
            }
        });
    }

    /** One line per finding, coloured by severity; selecting one enables Explain. */
    private void setUpFindingsList() {
        findings.setCellFactory(l -> new ListCell<>() {
            @Override
            protected void updateItem(Finding f, boolean empty) {
                super.updateItem(f, empty);
                getStyleClass().removeIf(s -> s.startsWith("sev-"));
                setText(empty || f == null ? null : SafeText.shorten(AiPresenter.findingLine(f)));
                if (!empty && f != null) {
                    getStyleClass().add("sev-" + f.severity().name().toLowerCase(Locale.ROOT));
                }
            }
        });
        findings.setPlaceholder(new Label("No findings yet: scan a file or replay a log first."));
        findings.getSelectionModel().selectedItemProperty().addListener((o, a, f) -> explain.setDisable(f == null));
    }

    /** The answer is plain text only; Explain and Retry online start a request. */
    private void setUpAnswerArea() {
        answer.setEditable(false);
        answer.setWrapText(true);
        answer.setPromptText("Select a finding and press Explain.");
        answer.getStyleClass().add("answer");
        error.getStyleClass().add("error-text");
        error.setWrapText(true);
        budget.getStyleClass().add("card-sub");
        explain.getStyleClass().add("primary-button");
        explain.setDisable(true);
        explain.setOnAction(e -> run(provider.getValue()));
        retry.getStyleClass().add("secondary-button");
        retry.setVisible(false);
        retry.setOnAction(e -> run(ExplanationService.AUTO));
    }

    private VBox findingsPanel() {
        VBox left = Ui.panel(Ui.section("FINDINGS"), findings);
        VBox.setVgrow(findings, Priority.ALWAYS);
        left.setPrefWidth(460);
        left.setMinWidth(360);
        return left;
    }

    private VBox explanationPanel() {
        HBox controls = new HBox(10, new Label("Explain with"), provider, explain, retry);
        controls.setAlignment(Pos.CENTER_LEFT);
        VBox right = Ui.panel(Ui.section("EXPLANATION"), controls, badges, answer, error, budget);
        VBox.setVgrow(answer, Priority.ALWAYS);
        HBox.setHgrow(right, Priority.ALWAYS);
        return right;
    }

    public Node node() {
        return root;
    }

    /** New findings arrived: reload the list, keeping the selected finding selected. */
    public void reload() {
        loadFindings();
    }

    private void loadFindings() {
        listLoads.run("ai-list", () -> new FindingRepository(coordinator.database()).findRecent(RECENT),
                list -> {
                    Finding selected = findings.getSelectionModel().getSelectedItem();
                    findings.getItems().setAll(list);
                    if (selected != null) {
                        list.stream().filter(f -> f.id() == selected.id()).findFirst().ifPresent(f -> findings.getSelectionModel().select(f));
                    }
                }, this::failed);
    }

    /** Findings view > Explain: put this finding first in the list, select it and explain it with the current choice. */
    public void explainFinding(long findingId) {
        UiTasks.run("ai-find", () -> new FindingRepository(coordinator.database()).findById(findingId), found -> found.ifPresent(f -> {
            findings.getItems().removeIf(x -> x.id() == f.id());
            findings.getItems().add(0, f);
            findings.getSelectionModel().select(0);
            run(provider.getValue());
        }), this::failed);
    }

    private void run(String choice) {
        Finding f = findings.getSelectionModel().getSelectedItem();
        if (f == null) {
            return;
        }
        explain.setDisable(true);
        answer.setText("Asking " + AiPresenter.label(choice) + "…");
        badges.getChildren().clear();
        error.setText("");
        UiTasks.await("ai-explain", coordinator.explain(f, choice), this::show, this::failed);
    }

    private void show(ExplanationService.Explanation e) {
        explain.setDisable(false);
        answer.setText(e.text());                         // plain text only: never rendered as HTML
        badges.getChildren().clear();
        for (String b : AiPresenter.badges(e)) {
            Label l = new Label(b);
            l.getStyleClass().addAll("badge", b.equals("offline fallback") ? "badge-warn" : "badge-info");
            badges.getChildren().add(l);
        }
        error.setText(e.error() == null ? "" : "Why the fallback: " + e.error());
        retry.setVisible(e.fellBack());
        updateBudget();
    }

    private void updateBudget() {
        budget.setText(AiPresenter.budgetText(coordinator.explanations().budgetUsage()));
    }

    private void failed(Exception e) {
        explain.setDisable(false);
        error.setText("Failed: " + e.getMessage());
    }
}
