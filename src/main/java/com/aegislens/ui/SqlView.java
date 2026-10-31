package com.aegislens.ui;

import com.aegislens.app.ScanCoordinator;
import com.aegislens.db.SqlConsole;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.collections.FXCollections;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

import java.util.List;

/**
 * The SQL view: a read-only console. Pick an example or type ONE SELECT, WITH or EXPLAIN statement, press Run (or
 * Ctrl+Enter) and see the rows in a table. SqlConsole refuses anything that writes; results stop at 500 rows.
 */
public final class SqlView {

    private final SqlConsole console;
    private final TextArea sql = new TextArea();
    private final TableView<List<String>> result = new TableView<>();
    private final Label status = new Label();
    private final Button run = new Button("Run  (Ctrl+Enter)");
    private final VBox root;

    public SqlView(ScanCoordinator coordinator) {
        this.console = new SqlConsole(coordinator.database());
        VBox header = Ui.header("SQL console", "Read-only: SELECT, WITH and EXPLAIN only, at most " + SqlConsole.MAX_ROWS
                + " rows. Tables: finding, scan_session, ioc, rule, audit_log... Views: v_finding_detail, v_daily_counts.");

        ComboBox<String> examples = new ComboBox<>(FXCollections.observableArrayList(ReportsPresenter.EXAMPLES.keySet()));
        examples.setPromptText("Example queries…");
        examples.setOnAction(e -> {
            if (examples.getValue() != null) {
                sql.setText(ReportsPresenter.EXAMPLES.get(examples.getValue()));
            }
        });
        sql.setPrefRowCount(5);
        sql.setWrapText(true);
        sql.getStyleClass().add("answer");
        sql.setText(ReportsPresenter.EXAMPLES.values().iterator().next());
        sql.setOnKeyPressed(e -> {
            if (e.getCode() == KeyCode.ENTER && e.isShortcutDown()) {
                runQuery();
                e.consume();
            }
        });
        run.getStyleClass().add("primary-button");
        run.setOnAction(e -> runQuery());
        HBox controls = new HBox(10, examples, run, status);
        controls.setAlignment(Pos.CENTER_LEFT);
        status.getStyleClass().add("card-sub");
        result.setPlaceholder(new Label("Run a query to see rows here."));
        VBox box = new VBox(10, sql, controls, result);
        box.getStyleClass().add("panel");
        VBox.setVgrow(result, Priority.ALWAYS);
        VBox.setVgrow(box, Priority.ALWAYS);
        root = new VBox(18, header, box);
        root.getStyleClass().add("dashboard");
    }

    public Node node() {
        return root;
    }

    private void runQuery() {
        String text = sql.getText();
        run.setDisable(true);
        status.getStyleClass().remove("error-text");
        status.setText("Running…");
        UiTasks.run("sql", () -> console.run(text), this::show, e -> {
            run.setDisable(false);
            status.setText(SafeText.shorten(e.getMessage()));
            status.getStyleClass().add("error-text");
        });
    }

    private void show(SqlConsole.Result r) {
        run.setDisable(false);
        result.getColumns().clear();
        for (int i = 0; i < r.columns().size(); i++) {
            int index = i;
            TableColumn<List<String>, String> c = new TableColumn<>(r.columns().get(i));
            c.setCellValueFactory(cell -> new ReadOnlyStringWrapper(
                    cell.getValue().get(index) == null ? "NULL" : SafeText.shorten(cell.getValue().get(index))));
            c.setPrefWidth(140);
            result.getColumns().add(c);
        }
        result.getItems().setAll(r.rows());
        status.setText(r.rows().size() + " row(s) in " + r.millis() + " ms" + (r.truncated() ? "  ·  stopped at "
                + SqlConsole.MAX_ROWS + " rows" : ""));
    }
}
