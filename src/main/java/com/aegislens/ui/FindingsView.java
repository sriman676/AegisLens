package com.aegislens.ui;

import com.aegislens.app.AnalystActions;
import com.aegislens.app.Branding;
import com.aegislens.app.ScanCoordinator;
import com.aegislens.db.DataExchange;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.FindingSearch;
import com.aegislens.db.ReportRepository;
import com.aegislens.db.ReportRepository.DetailRow;
import com.aegislens.response.HtmlReportExporter;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.SelectionMode;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.control.cell.ComboBoxTableCell;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.LongConsumer;

/**
 * The Findings explorer: search (TextField), severity and module (ComboBox), status (RadioButtons in a ToggleGroup), a
 * TreeView of module > severity counts, and a multi-select TableView with inline status editing, bulk actions,
 * "Load more" keyset paging, and CSV/JSON export and CSV import. All database work runs off the FX thread.
 */
public final class FindingsView {

    /** Rows fetched per page. */
    public static final int PAGE = 200;
    private static final List<String> STATUS_CODES = List.of("OPEN", "RESOLVED", "FALSE_POSITIVE");

    private final ScanCoordinator coordinator;
    private final LatestOnly pageLoads = new LatestOnly();
    private final LatestOnly treeLoads = new LatestOnly();
    private final Window owner;
    private final Consumer<Dialog<?>> styler;
    private final FindingSearch search;
    private final FindingRepository findings;
    private final ReportRepository reports;
    private final DataExchange exchange;
    private final AnalystActions actions;
    private final LongConsumer explainer;

    private final TextField text = new TextField();
    private final ComboBox<String> severity = new ComboBox<>(FXCollections.observableArrayList(FindingsPresenter.SEVERITIES));
    private final ComboBox<String> module = new ComboBox<>(FXCollections.observableArrayList(FindingsPresenter.MODULES));
    private final ToggleGroup status = new ToggleGroup();
    private final TreeView<String> tree = new TreeView<>();
    private final ObservableList<DetailRow> rows = FXCollections.observableArrayList();
    private final TableView<DetailRow> table = new TableView<>(rows);
    private final Button loadMore = new Button("Load more");
    private final Label footer = new Label();
    private final Label message = new Label();
    private final VBox root;
    private FindingSearch.Filter current = FindingSearch.Filter.ALL;

    /** explainer opens the AI view for a finding id. */
    public FindingsView(ScanCoordinator coordinator, Window owner, Consumer<Dialog<?>> styler, LongConsumer explainer) {
        this.coordinator = coordinator;
        this.owner = owner;
        this.styler = styler;
        this.search = new FindingSearch(coordinator.database());
        this.findings = new FindingRepository(coordinator.database());
        this.reports = new ReportRepository(coordinator.database());
        this.exchange = new DataExchange(coordinator.database());
        this.actions = new AnalystActions(coordinator);
        this.explainer = explainer;

        VBox header = Ui.header("Findings", "Search, filter, resolve or dismiss findings; export them for a report or import a colleague's.");

        VBox left = Ui.panel(Ui.section("EXPLORER"), tree);
        VBox.setVgrow(tree, Priority.ALWAYS);
        left.setPrefWidth(250);
        left.setMinWidth(220);
        VBox right = Ui.panel(filters(), table, actions(), new HBox(12, loadMore, footer));
        VBox.setVgrow(table, Priority.ALWAYS);
        HBox.setHgrow(right, Priority.ALWAYS);
        HBox body = new HBox(16, left, right);
        VBox.setVgrow(body, Priority.ALWAYS);
        message.getStyleClass().add("card-sub");
        root = new VBox(18, header, body, message);
        root.getStyleClass().add("dashboard");

        buildTable();
        tree.setShowRoot(true);
        tree.getSelectionModel().selectedItemProperty().addListener((o, a, item) -> fromTree(item));
        loadMore.getStyleClass().add("secondary-button");
        loadMore.setOnAction(e -> loadPage(false));
        footer.getStyleClass().add("card-sub");
        refresh();
    }

    public Node node() {
        return root;
    }

    /** Re-runs the search and reloads the tree (after a scan, an import or a bulk action). */
    public void refresh() {
        current = FindingsPresenter.filter(text.getText(), severity.getValue(), selectedStatus(), module.getValue());
        loadPage(true);
        treeLoads.run("findings-tree", () -> FindingsPresenter.tree(reports.perModuleAndSeverity()), this::showTree, this::fail);
    }

    // ---------------------------------------------------------------- layout

    private Node filters() {
        text.setPromptText("Search description or target (e.g. 203.0.113.45 or \"failed root\")");
        text.setOnAction(e -> refresh());
        HBox.setHgrow(text, Priority.ALWAYS);
        severity.setValue(FindingsPresenter.ANY);
        module.setValue(FindingsPresenter.ANY);
        severity.setOnAction(e -> refresh());
        module.setOnAction(e -> refresh());
        HBox statuses = new HBox(10);
        for (String label : FindingsPresenter.STATUS_LABELS) {
            RadioButton r = new RadioButton(label);
            r.setToggleGroup(status);
            r.setUserData(label);
            r.setSelected(label.equals(FindingsPresenter.ANY));
            statuses.getChildren().add(r);
        }
        status.selectedToggleProperty().addListener((o, a, now) -> refresh());
        Button go = new Button("Search");
        go.getStyleClass().add("primary-button");
        go.setOnAction(e -> refresh());
        HBox first = new HBox(10, text, go);
        HBox second = new HBox(10, new Label("Severity"), severity, new Label("Module"), module, new Label("Status"), statuses);
        first.setAlignment(Pos.CENTER_LEFT);
        second.setAlignment(Pos.CENTER_LEFT);
        return new VBox(8, first, second);
    }

    private void buildTable() {
        table.getColumns().add(Ui.column("Time", 110, r -> SafeText.time(r.createdAt())));
        TableColumn<DetailRow, String> sev = Ui.column("Severity", 80, DetailRow::severity);
        sev.setCellFactory(c -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                getStyleClass().removeIf(s -> s.startsWith("sev-"));
                setText(empty ? null : item);
                if (!empty && item != null) {
                    getStyleClass().addAll("sev-pill", "sev-" + item.toLowerCase(Locale.ROOT));
                }
            }
        });
        table.getColumns().add(sev);
        table.getColumns().add(Ui.column("Score", 50, r -> String.valueOf(r.score())));
        table.getColumns().add(Ui.column("Rule", 70, DetailRow::ruleId));
        table.getColumns().add(Ui.column("Module", 85, DetailRow::module));
        table.getColumns().add(Ui.column("Target", 130, r -> SafeText.target(r.target())));
        TableColumn<DetailRow, String> st = Ui.column("Status ✎", 125, DetailRow::status);
        st.setCellFactory(ComboBoxTableCell.forTableColumn(FXCollections.observableArrayList(STATUS_CODES)));
        st.setOnEditCommit(e -> bulk(List.of(e.getRowValue().id()), ids -> findings.updateStatusMany(ids, e.getNewValue()),
                "Status changed to " + e.getNewValue()));
        table.getColumns().add(st);
        table.getColumns().add(Ui.column("What happened", 300, r -> SafeText.shorten(r.description())));
        table.setEditable(true);
        table.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.setPlaceholder(new Label("No findings match. Clear the search or pick \"All\"."));
    }

    private Node actions() {
        Button resolve = Ui.button("Resolve selected", "secondary-button",
                () -> bulk(selectedIds(), ids -> findings.updateStatusMany(ids, "RESOLVED"), "Resolved"));
        Button dismiss = Ui.button("False positive", "secondary-button",
                () -> bulk(selectedIds(), ids -> findings.updateStatusMany(ids, "FALSE_POSITIVE"), "Marked false positive"));
        Button target = Ui.button("Dismiss whole target", "secondary-button", this::dismissTarget);
        Button delete = Ui.button("Delete selected", "danger-button", this::deleteSelected);
        Button csv = Ui.button("Export CSV", "secondary-button", () -> exportFindings(DataExchange.Format.CSV));
        Button json = Ui.button("Export JSON", "secondary-button", () -> exportFindings(DataExchange.Format.JSON));
        Button report = Ui.button("Export HTML report", "secondary-button", this::exportReport);
        Button imp = Ui.button("Import CSV", "secondary-button", this::importFindings);
        Button explain = Ui.button("Explain (AI)", "primary-button", () -> one(r -> explainer.accept(r.id())));
        Button block = Ui.button("Record block", "secondary-button", () -> one(this::recordBlock));
        Button trust = Ui.button("Trust target", "secondary-button", () -> one(this::trust));
        Button copy = Ui.button("Copy as text", "secondary-button", () -> one(this::copy));
        return new FlowPane(8, 8, explain, resolve, dismiss, target, block, trust, copy, delete, csv, json, report, imp);
    }

    // ---------------------------------------------------------------- actions

    private void loadPage(boolean fresh) {
        Long before = fresh || rows.isEmpty() ? null : rows.get(rows.size() - 1).id();
        FindingSearch.Filter filter = current;
        UiTasks.Work<List<DetailRow>> work = () -> search.search(filter, before, PAGE);
        Consumer<List<DetailRow>> show = page -> {
            if (fresh) {
                List<Long> selected = selectedIds();               // live updates keep the analyst's selection
                rows.setAll(page);
                rows.stream().filter(r -> selected.contains(r.id())).forEach(r -> table.getSelectionModel().select(r));
            } else {
                rows.addAll(page);
            }
            loadMore.setDisable(page.size() < PAGE);
            footer.setText(FindingsPresenter.footer(rows.size(), page.size() == PAGE, search.fullText()));
        };
        if (fresh) {
            pageLoads.run("findings-page", work, show, this::fail);       // live reloads never pile up
        } else {
            UiTasks.run("findings-more", work, show, this::fail);
        }
    }

    private void showTree(Map<String, Map<String, Integer>> data) {
        int all = 0;
        TreeItem<String> top = new TreeItem<>();
        for (Map.Entry<String, Map<String, Integer>> m : data.entrySet()) {
            int total = FindingsPresenter.total(m.getValue());
            all += total;
            TreeItem<String> moduleItem = new TreeItem<>(FindingsPresenter.nodeText(m.getKey(), total));
            moduleItem.setExpanded(true);
            for (Map.Entry<String, Integer> s : m.getValue().entrySet()) {
                moduleItem.getChildren().add(new TreeItem<>(FindingsPresenter.nodeText(s.getKey(), s.getValue())));
            }
            top.getChildren().add(moduleItem);
        }
        top.setValue(FindingsPresenter.nodeText("All findings", all));
        top.setExpanded(true);
        tree.setRoot(top);
    }

    /** Clicking "MALWARE (3)" filters by module; clicking a severity under it filters by both. */
    private void fromTree(TreeItem<String> item) {
        if (item == null) {
            return;
        }
        String name = item.getValue().replaceAll(" \\(\\d+\\)$", "");
        if (item.getParent() == null) {
            module.setValue(FindingsPresenter.ANY);
            severity.setValue(FindingsPresenter.ANY);
        } else if (item.getParent().getParent() == null) {
            module.setValue(name);
            severity.setValue(FindingsPresenter.ANY);
        } else {
            module.setValue(item.getParent().getValue().replaceAll(" \\(\\d+\\)$", ""));
            severity.setValue(name);
        }
        refresh();
    }

    /** Runs an action on the single selected row, or explains that one row must be selected. */
    private void one(Consumer<DetailRow> action) {
        DetailRow row = table.getSelectionModel().getSelectedItem();
        if (row == null) {
            message.setText("Select a finding first.");
        } else {
            action.accept(row);
        }
    }

    private void recordBlock(DetailRow row) {
        if (confirm("Record " + SafeText.shorten(row.target()) + " as blocked? It goes into the blocklist export; "
                + "AegisLens never changes your firewall.")) {
            UiTasks.run("block", () -> actions.recordBlock(row.target(), row.ruleId() + ": " + row.description()),
                    message::setText, this::fail);
        }
    }

    private void trust(DetailRow row) {
        if (confirm("Trust " + SafeText.shorten(row.target()) + "? New findings for it will be dropped.")) {
            UiTasks.run("trust", () -> actions.trust(row.target()), message::setText, this::fail);
        }
    }

    private void copy(DetailRow row) {
        UiTasks.run("copy", () -> findings.findById(row.id()).map(AnalystActions::asText).orElse(""), text -> {
            ClipboardContent content = new ClipboardContent();
            content.putString(text);
            Clipboard.getSystemClipboard().setContent(content);
            message.setText("Copied finding " + row.id() + " as text.");
        }, this::fail);
    }

    private void deleteSelected() {
        List<Long> ids = selectedIds();
        if (!ids.isEmpty() && confirm("Delete " + ids.size() + " finding(s) for good? This cannot be undone.")) {
            bulk(ids, findings::deleteMany, "Deleted");
        }
    }

    private void dismissTarget() {
        DetailRow row = table.getSelectionModel().getSelectedItem();
        if (row != null && confirm("Mark every OPEN finding for " + SafeText.shorten(row.target()) + " as a false positive?")) {
            UiTasks.run("findings-target", () -> findings.markTargetFalsePositive(row.target()),
                    n -> done(n + " finding(s) marked false positive"), this::fail);
        }
    }

    /** File > Export findings… also lands here. Exports what the current filter shows (all pages). */
    public void exportFindings(DataExchange.Format format) {
        File file = chooseSaveFile("aegislens-findings", format == DataExchange.Format.CSV ? "csv" : "json");
        if (file != null) {
            FindingSearch.Filter filter = current;
            UiTasks.run("findings-export", () -> exchange.export(filter, file.toPath(), format),
                    n -> message.setText("Exported " + n + " finding(s) to " + file.getName()), this::fail);
        }
    }

    /** File > Export HTML report… also lands here: a one-page report (counts, attackers, rules, newest findings). */
    public void exportReport() {
        File file = chooseSaveFile("aegislens-report", "html");
        if (file != null) {
            UiTasks.run("report", () -> new HtmlReportExporter(coordinator.database()).export(file.toPath(), Instant.now(), Branding.load(coordinator)),
                    n -> message.setText("Report with " + n + " finding(s) written to " + file.getName()), this::fail);
        }
    }

    private File chooseSaveFile(String name, String ext) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Save " + ext.toUpperCase(Locale.ROOT));
        chooser.setInitialFileName(name + "." + ext);
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(ext.toUpperCase(Locale.ROOT), "*." + ext));
        return chooser.showSaveDialog(owner);
    }

    /** File > Import findings… also lands here. One bad row and nothing is imported. */
    public void importFindings() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Import findings (CSV written by AegisLens)");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV", "*.csv"));
        File file = chooser.showOpenDialog(owner);
        if (file != null) {
            UiTasks.run("findings-import", () -> exchange.importCsv(file.toPath()),
                    n -> done("Imported " + n + " finding(s) from " + file.getName()), this::fail);
        }
    }

    @FunctionalInterface
    private interface IdWork {
        int apply(List<Long> ids) throws Exception;
    }

    private void bulk(List<Long> ids, IdWork work, String verb) {
        if (ids.isEmpty()) {
            message.setText("Select one or more rows first (Ctrl/Shift + click).");
            return;
        }
        UiTasks.run("findings-bulk", () -> work.apply(ids), n -> done(verb + ": " + n + " finding(s)"), this::fail);
    }

    private void done(String text) {
        message.setText(text);
        refresh();
    }

    private void fail(Exception e) {
        message.setText("Failed: " + SafeText.shorten(e.getMessage()));
    }

    private boolean confirm(String question) {
        Alert a = new Alert(Alert.AlertType.CONFIRMATION, question, ButtonType.OK, ButtonType.CANCEL);
        styler.accept(a);
        return a.showAndWait().filter(b -> b == ButtonType.OK).isPresent();
    }

    // ---------------------------------------------------------------- helpers

    private List<Long> selectedIds() {
        return table.getSelectionModel().getSelectedItems().stream().map(DetailRow::id).toList();
    }

    private String selectedStatus() {
        return status.getSelectedToggle() == null ? FindingsPresenter.ANY : (String) status.getSelectedToggle().getUserData();
    }

}
