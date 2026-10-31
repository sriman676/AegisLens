package com.aegislens.ui;

import com.aegislens.app.ScanCoordinator;
import com.aegislens.app.ScanCoordinator.WebCheck;
import com.aegislens.core.Finding;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * The Web view: type an address and check it. "Static checks only" sends nothing anywhere; "Also fetch the page once"
 * first asks for consent, then makes ONE request through the SSRF guard (public addresses only, 3 redirects, 5 s,
 * 1 MB). Reasons are shown as plain text. A text file of addresses can be checked statically in one go.
 */
public final class WebCheckView {

    private final ScanCoordinator coordinator;
    private final Window owner;
    private final Consumer<Dialog<?>> styler;
    private final TextField url = new TextField();
    private final RadioButton staticOnly = new RadioButton("Static checks only (nothing is sent)");
    private final RadioButton fetch = new RadioButton("Also fetch the page once (sends one request)");
    private final Label verdict = new Label("Type an address and press Check.");
    private final TextArea reasons = new TextArea();
    private final TableView<WebCheck> batch = new TableView<>();
    private final Button check = Ui.button("Check", "primary-button", this::checkOne);
    private boolean consented;
    private final VBox root;

    public WebCheckView(ScanCoordinator coordinator, Window owner, Consumer<Dialog<?>> styler) {
        this.coordinator = coordinator;
        this.owner = owner;
        this.styler = styler;
        VBox header = Ui.header("Web", "Check a link before you open it: look-alike domains, hidden destinations, "
                + "injection patterns and threat lists. Use addresses you are allowed to test.");
        url.setPromptText("https://paypa1-secure-login.example.test/verify");
        url.setOnAction(e -> checkOne());
        HBox.setHgrow(url, Priority.ALWAYS);
        ToggleGroup mode = new ToggleGroup();
        staticOnly.setToggleGroup(mode);
        fetch.setToggleGroup(mode);
        staticOnly.setSelected(true);
        verdict.getStyleClass().add("page-subtitle");
        reasons.setEditable(false);
        reasons.setWrapText(true);
        reasons.setPrefRowCount(10);
        reasons.getStyleClass().add("answer");

        batch.getColumns().add(Ui.column("Address", 420, w -> SafeText.shorten(w.url())));
        batch.getColumns().add(Ui.column("Result", 300, w -> WebPresenter.verdict(w.findings())));
        batch.getColumns().add(Ui.column("Rules", 150, w -> String.join(" ", w.findings().stream().map(Finding::ruleId).toList())));
        batch.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        batch.setPlaceholder(new Label("Check a whole list: one address per line in a text file."));
        batch.setPrefHeight(220);
        batch.getSelectionModel().selectedItemProperty().addListener((o, a, w) -> {
            if (w != null) {
                show(w);
            }
        });

        HBox row = new HBox(10, url, check);
        HBox modes = new HBox(16, staticOnly, fetch);
        row.setAlignment(Pos.CENTER_LEFT);
        VBox one = Ui.panel(Ui.section("CHECK ONE ADDRESS"), row, modes, verdict, reasons);
        VBox many = Ui.panel(new HBox(12, Ui.section("CHECK A LIST (STATIC ONLY)"),
                Ui.button("Choose a text file...", "secondary-button", this::checkFile)), batch);
        root = new VBox(18, header, one, many);
        root.getStyleClass().add("dashboard");
    }

    public Node node() {
        return root;
    }

    /** Scan > Check URL... puts the cursor in the address field. */
    public void focus() {
        url.requestFocus();
    }

    private void checkOne() {
        boolean wantsFetch = fetch.isSelected();
        if (wantsFetch && !consented && !askConsent()) {
            return;
        }
        check.setDisable(true);
        verdict.setText(wantsFetch ? "Checking and fetching once…" : "Checking…");
        UiTasks.await("web", coordinator.checkUrl(url.getText(), wantsFetch), w -> {
            check.setDisable(false);
            show(w);
        }, e -> {
            check.setDisable(false);
            verdict.setText("Not checked: " + SafeText.shorten(e.getMessage()));
            reasons.clear();
        });
    }

    private void show(WebCheck w) {
        verdict.setText(WebPresenter.verdict(w.findings()));
        List<String> lines = new ArrayList<>();
        if (w.fetched() != null) {
            lines.add("Fetched " + w.fetched().finalUrl() + " (HTTP " + w.fetched().status() + ", "
                    + (w.fetched().chain().size() - 1) + " redirect(s))");
        }
        for (Finding f : w.findings()) {
            lines.addAll(WebPresenter.reasons(f));
        }
        reasons.setText(String.join("\n", lines.stream().map(SafeText::shorten).toList()));
    }

    /** Asked once per session: what will happen when the page is fetched. */
    private boolean askConsent() {
        Alert a = new Alert(Alert.AlertType.CONFIRMATION, "AegisLens will send ONE request to this address from your "
                + "computer (the site sees your IP address). Only public addresses are allowed, at most 3 redirects, "
                + "5 seconds and 1 MB. Fetch only sites you are allowed to test. Continue?", ButtonType.OK, ButtonType.CANCEL);
        a.setHeaderText("Fetch the page?");
        styler.accept(a);
        consented = a.showAndWait().filter(b -> b == ButtonType.OK).isPresent();
        return consented;
    }

    private void checkFile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Text file with one address per line");
        File file = chooser.showOpenDialog(owner);
        if (file == null) {
            return;
        }
        verdict.setText("Checking the list…");
        UiTasks.run("web-batch", () -> {
            List<WebCheck> results = new ArrayList<>();
            for (String address : WebPresenter.addresses(Files.readAllLines(file.toPath(), StandardCharsets.UTF_8))) {
                try {
                    results.add(coordinator.checkUrl(address, false).get(30, TimeUnit.SECONDS));
                } catch (Exception bad) {                  // one bad line never stops the list
                    results.add(new WebCheck(address, List.of(), null));
                }
            }
            return results;
        }, results -> {
            batch.getItems().setAll(results);
            verdict.setText(results.size() + " address(es) checked; select one to see why.");
        }, e -> verdict.setText("Could not read the file: " + SafeText.shorten(e.getMessage())));
    }
}
