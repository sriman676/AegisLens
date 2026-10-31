package com.aegislens.ui;

import com.aegislens.app.ScanCoordinator;
import com.aegislens.db.ReportRepository;
import com.aegislens.db.ReportRepository.Query;
import com.aegislens.db.ReportRepository.RuleCount;
import com.aegislens.db.ReportRepository.TargetStats;
import javafx.collections.FXCollections;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.StackedBarChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Spinner;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The Reports view: what the SQL in ReportRepository finds. A stacked bar chart of findings per day and severity (view +
 * GROUP BY), rules that fired at least N times (HAVING), top attackers (aggregates), targets with more than N findings
 * (derived-table subquery), targets on a threat list (IN subquery), and the query plan SQLite uses for any of them.
 */
public final class ReportsView {

    private static final int TOP = 10;

    private final ReportRepository reports;
    private final LatestOnly loads = new LatestOnly();
    private final CategoryAxis days = new CategoryAxis();
    private final StackedBarChart<String, Number> chart = new StackedBarChart<>(days, new NumberAxis());
    private final TableView<RuleCount> rules = new TableView<>();
    private final TableView<TargetStats> attackers = targetTable();
    private final TableView<TargetStats> busy = targetTable();
    private final TableView<TargetStats> ioc = targetTable();
    private final Spinner<Integer> minRule = new Spinner<>(1, 1000, 2);
    private final Spinner<Integer> moreThan = new Spinner<>(0, 1000, 5);
    private final ComboBox<Query> planFor = new ComboBox<>(FXCollections.observableArrayList(Query.values()));
    private final TextArea plan = new TextArea();
    private final Label message = new Label();
    private final ScrollPane root;

    public ReportsView(ScanCoordinator coordinator) {
        this.reports = new ReportRepository(coordinator.database());
        VBox header = Ui.header("Reports", "Every number here is one SQL query (views, JOIN, GROUP BY/HAVING, subqueries). False positives are left out.");
        Region gap = new Region();
        HBox.setHgrow(gap, Priority.ALWAYS);
        HBox head = new HBox(10, header, gap);
        head.setAlignment(Pos.CENTER_LEFT);

        chart.setAnimated(false);
        chart.setLegendVisible(true);
        chart.setPrefHeight(260);
        rules.getColumns().add(Ui.column("Rule", 90, RuleCount::ruleId));
        rules.getColumns().add(Ui.column("Name", 220, r -> SafeText.shorten(r.ruleName())));
        rules.getColumns().add(Ui.column("Findings", 80, r -> String.valueOf(r.count())));
        rules.getColumns().add(Ui.column("Top score", 80, r -> String.valueOf(r.maxScore())));
        rules.setPrefHeight(260);
        rules.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        minRule.valueProperty().addListener((o, a, b) -> refresh());
        moreThan.valueProperty().addListener((o, a, b) -> refresh());
        minRule.setPrefWidth(80);
        moreThan.setPrefWidth(80);

        HBox row1 = new HBox(16, grow(Ui.panel(Ui.section("FINDINGS PER DAY (" + ReportsPresenter.DAYS + " DAYS)"), chart)),
                grow(Ui.panel(new HBox(8, Ui.section("RULES THAT FIRED AT LEAST"), minRule, Ui.section("TIMES (HAVING)")), rules)));
        HBox row2 = new HBox(16, grow(Ui.panel(Ui.section("TOP ATTACKERS (INTRUSION)"), attackers)),
                grow(Ui.panel(new HBox(8, Ui.section("MORE THAN"), moreThan, Ui.section("FINDINGS (SUBQUERY)")), busy)),
                grow(Ui.panel(Ui.section("TARGETS ON A THREAT LIST (IN SUBQUERY)"), ioc)));
        planFor.setValue(Query.PER_RULE);
        planFor.setOnAction(e -> showPlan());
        plan.setEditable(false);
        plan.setPrefRowCount(7);
        plan.setWrapText(true);
        plan.getStyleClass().add("answer");
        VBox planBox = Ui.panel(new HBox(8, Ui.section("QUERY PLAN (EXPLAIN QUERY PLAN) FOR"), planFor), plan);
        message.getStyleClass().add("error-text");
        VBox content = new VBox(16, head, row1, row2, planBox, message);
        content.getStyleClass().add("dashboard");
        root = new ScrollPane(content);
        root.setFitToWidth(true);
        root.getStyleClass().add("page-scroll");
        refresh();
    }

    public Node node() {
        return root;
    }

    /** Re-runs every report in the background. */
    public void refresh() {
        int min = minRule.getValue();
        int more = moreThan.getValue();
        loads.run("reports", () -> new Data(reports.perDay(ReportsPresenter.DAYS, Instant.now()), reports.perRule(min),
                reports.topAttackers(TOP), reports.targetsWithMoreThan(more), reports.findingsWithIocTarget()),
                this::show, e -> message.setText("Failed: " + SafeText.shorten(e.getMessage())));
        showPlan();
    }

    private record Data(List<ReportRepository.DayCount> perDay, List<RuleCount> rules, List<TargetStats> attackers,
                        List<TargetStats> busy, List<TargetStats> ioc) {
    }

    private void show(Data d) {
        chart.getData().clear();
        for (Map.Entry<String, Map<String, Integer>> s
                : ReportsPresenter.series(d.perDay(), ReportsPresenter.DAYS, Instant.now()).entrySet()) {
            XYChart.Series<String, Number> series = new XYChart.Series<>();
            series.setName(s.getKey());
            s.getValue().forEach((day, n) -> series.getData().add(new XYChart.Data<>(ReportsPresenter.shortDay(day), n)));
            chart.getData().add(series);
        }
        Map<String, Integer> totals = new LinkedHashMap<>();
        chart.getData().forEach(series -> totals.put(series.getName(),
                series.getData().stream().mapToInt(p -> p.getYValue().intValue()).sum()));
        chart.setAccessibleText(DashboardPresenter.spoken("Findings per day, last " + ReportsPresenter.DAYS + " days", totals));
        rules.getItems().setAll(d.rules());
        attackers.getItems().setAll(d.attackers());
        busy.getItems().setAll(d.busy());
        ioc.getItems().setAll(d.ioc());
        message.setText("");
    }

    private void showPlan() {
        Query q = planFor.getValue();
        UiTasks.run("reports-plan", () -> q.sql() + "\n\n" + reports.explain(q), plan::setText,
                e -> plan.setText("Failed: " + e.getMessage()));
    }

    private static TableView<TargetStats> targetTable() {
        TableView<TargetStats> t = new TableView<>();
        t.getColumns().add(Ui.column("Target", 150, r -> SafeText.target(r.target())));
        t.getColumns().add(Ui.column("Findings", 70, r -> String.valueOf(r.count())));
        t.getColumns().add(Ui.column("Top", 50, r -> String.valueOf(r.maxScore())));
        t.getColumns().add(Ui.column("Last seen", 150, r -> SafeText.time(r.lastSeen())));
        t.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        t.setPlaceholder(new Label("Nothing yet"));
        t.setPrefHeight(260);
        return t;
    }

    private static VBox grow(VBox box) {
        HBox.setHgrow(box, Priority.ALWAYS);
        return box;
    }

}
