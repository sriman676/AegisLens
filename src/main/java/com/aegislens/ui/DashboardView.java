package com.aegislens.ui;

import com.aegislens.core.Finding;
import com.aegislens.core.Severity;
import com.aegislens.db.FindingRepository.TargetCount;
import javafx.animation.FadeTransition;
import javafx.animation.Interpolator;
import javafx.animation.KeyFrame;
import javafx.animation.ParallelTransition;
import javafx.animation.RotateTransition;
import javafx.animation.ScaleTransition;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.chart.AreaChart;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableRow;
import javafx.scene.control.TableView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Circle;
import javafx.util.Duration;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The Dashboard: a header, four bold severity cards (icon, count, 24 h sparkline), a stacked 24 h timeline of findings,
 * a donut of findings per module, the live findings table, the top attackers and a status bar. The look comes entirely
 * from the active theme's stylesheet. Data comes from DashboardPresenter on a background thread every 5 seconds; new
 * findings arrive live through onFinding (any thread, moved to the FX thread with Platform.runLater). A CRITICAL finding
 * makes its card pulse (scale + fade) and spins the logo (rotate). Log text is only ever shown as plain text.
 */
public final class DashboardView {

    public static final Duration REFRESH = Duration.seconds(30);
    public static final int MAX_ROWS = 500;
    private static final Severity[] CARD_ORDER = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW};
    private static final Map<Severity, String> CARD_ICON = Map.of(Severity.CRITICAL, Icons.CRITICAL, Severity.HIGH, Icons.HIGH,
            Severity.MEDIUM, Icons.MEDIUM, Severity.LOW, Icons.LOW);
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("MMM dd HH:mm:ss", Locale.ENGLISH)
            .withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter CLOCK = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());
    private static final Logger LOG = Logger.getLogger(DashboardView.class.getName());

    private final DashboardPresenter presenter;
    private final Node spinner;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "aegislens-ui-refresh");
        t.setDaemon(true);
        t.setPriority(Thread.MIN_PRIORITY);
        return t;
    });
    private boolean loading;                      // FX thread only, like loadAgain
    private boolean loadAgain;
    private final Map<Severity, VBox> cards = new EnumMap<>(Severity.class);
    private final Map<Severity, Label> cardValues = new EnumMap<>(Severity.class);
    private final Map<Severity, Label> cardTrend = new EnumMap<>(Severity.class);
    private final Map<Severity, Sparkline> sparklines = new EnumMap<>(Severity.class);
    private final Map<Severity, XYChart.Series<String, Number>> timelineSeries = new EnumMap<>(Severity.class);
    private final PieChart modulePie = new PieChart();
    private AreaChart<String, Number> timelineChart;
    private final Label donutTotal = new Label("0");
    private final Label updated = new Label("Loading…");
    private final ListView<String> attackers = new ListView<>();
    private final ObservableList<Finding> rows = FXCollections.observableArrayList();
    private final List<Label> statusLabels = new ArrayList<>();
    private final BorderPane root = new BorderPane();
    private Timeline timeline;
    private Timeline feedTimer;
    private final FindingsFeed feed = new FindingsFeed();

    /** spinner is the node that rotates on a CRITICAL alert (the logo in the sidebar). */
    public DashboardView(DashboardPresenter presenter, Node spinner) {
        this.presenter = presenter;
        this.spinner = spinner;
        VBox content = new VBox(header(), cardsRow(), chartsRow(), bottomRow());
        content.getStyleClass().add("dashboard");
        ScrollPane scroll = new ScrollPane(content);
        scroll.setFitToWidth(true);
        scroll.getStyleClass().add("page-scroll");
        root.setCenter(scroll);
        root.setBottom(statusBar());
    }

    public Node node() {
        return root;
    }

    /** New findings arrived: redraw the cards, charts and lists now (called at most every 400 ms). */
    public void refreshNow() {
        refresh();
    }

    /** Loads the data now, then again every REFRESH so the "last 24 hours" window moves even when nothing happens. */
    public void start() {
        refresh();
        timeline = new Timeline(new KeyFrame(REFRESH, e -> refresh()));
        timeline.setCycleCount(Timeline.INDEFINITE);
        timeline.play();
        feedTimer = new Timeline(new KeyFrame(Duration.millis(FindingsFeed.PERIOD_MS), e -> showNewFindings()));
        feedTimer.setCycleCount(Timeline.INDEFINITE);
        feedTimer.play();
    }

    public void stop() {
        if (timeline != null) {
            timeline.stop();
            feedTimer.stop();
        }
        worker.shutdownNow();
    }

    /** A finding was saved (called on the persister thread): only queued here, shown by showNewFindings. */
    public void onFinding(Finding f) {
        feed.offer(f);
    }

    /** Every 250 ms on the FX thread: at most one batch of new findings, and at most one alarm per batch. */
    private void showNewFindings() {
        List<Finding> batch = feed.drain();
        boolean critical = false;
        for (Finding f : batch) {
            rows.add(0, f);
            Label value = cardValues.get(f.severity());
            value.setText(String.valueOf(Integer.parseInt(value.getText()) + 1));
            critical |= f.severity() == Severity.CRITICAL;
        }
        if (rows.size() > MAX_ROWS) {
            rows.remove(MAX_ROWS, rows.size());
        }
        if (critical) {
            alarm();
        }
    }

    /** FX thread only. One load at a time: a request made during a load runs once after it (see LatestOnly). */
    private void refresh() {
        if (loading) {
            loadAgain = true;
            return;
        }
        loading = true;
        worker.submit(() -> {
            try {
                DashboardPresenter.Snapshot s = presenter.snapshot();
                String feedLine = presenter.feedLine();
                Platform.runLater(() -> {
                    apply(s);
                    statusLabels.get(4).setText(feedLine);
                    loaded();
                });
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Dashboard refresh failed", e);
                Platform.runLater(this::loaded);
            }
        });
    }

    private void loaded() {
        loading = false;
        if (loadAgain) {
            loadAgain = false;
            refresh();
        }
    }

    private void apply(DashboardPresenter.Snapshot s) {
        Map<String, Integer> perSeverity = new LinkedHashMap<>();
        for (Severity sev : Severity.values()) {
            cardValues.get(sev).setText(String.valueOf(s.bySeverity().getOrDefault(sev, 0)));
            int[] hours = s.hourly().getOrDefault(sev, new int[DashboardPresenter.HOURS]);
            sparklines.get(sev).setValues(hours);
            int last24 = 0;
            for (int h : hours) {
                last24 += h;
            }
            cardTrend.get(sev).setText(last24 + " in the last 24 h");
            sparklines.get(sev).setAccessibleText(sev + ": " + last24 + " in the last 24 hours");
            perSeverity.put(sev.name(), last24);
        }
        timelineChart.setAccessibleText(DashboardPresenter.spoken("Findings in the last 24 hours", perSeverity));
        modulePie.setAccessibleText(DashboardPresenter.spoken("Findings by module", s.byModule()));
        List<String> labels = DashboardPresenter.hourLabels(s.takenAt(), ZoneId.systemDefault());
        for (Map.Entry<Severity, XYChart.Series<String, Number>> e : timelineSeries.entrySet()) {
            int[] hours = s.hourly().getOrDefault(e.getKey(), new int[DashboardPresenter.HOURS]);
            List<XYChart.Data<String, Number>> points = new ArrayList<>();
            for (int i = 0; i < labels.size(); i++) {
                points.add(new XYChart.Data<>(labels.get(i), hours[i]));
            }
            e.getValue().getData().setAll(points);
        }
        modulePie.getData().setAll(s.byModule().entrySet().stream()
                .map(e -> new PieChart.Data(e.getKey().charAt(0) + e.getKey().substring(1).toLowerCase(Locale.ROOT)
                        + " " + e.getValue(), e.getValue())).toList());
        donutTotal.setText(String.valueOf(s.total()));
        List<String> top = new ArrayList<>();
        for (TargetCount t : s.topTargets()) {
            top.add(SafeText.shorten(DashboardPresenter.attackerLine(t)));
        }
        attackers.getItems().setAll(top);
        if (rows.isEmpty()) {
            rows.setAll(s.recent());
        }
        List<String> items = DashboardPresenter.statusItems(s);
        for (int i = 0; i < statusLabels.size() && i < items.size(); i++) {
            statusLabels.get(i).setText(items.get(i));
        }
        updated.setText("Last 24 hours  ·  updated " + CLOCK.format(s.takenAt()));
    }

    private Node header() {
        Label title = new Label("Security overview");
        title.getStyleClass().add("page-title");
        updated.getStyleClass().add("page-subtitle");
        return new VBox(2, title, updated);
    }

    private HBox cardsRow() {
        HBox row = new HBox(16);
        for (Severity sev : CARD_ORDER) {
            String cls = "sev-" + sev.name().toLowerCase(Locale.ROOT);
            StackPane badge = new StackPane(Icons.icon(CARD_ICON.get(sev), 20, cls));
            badge.getStyleClass().addAll("card-badge", cls);
            Label title = new Label(sev.name());
            title.getStyleClass().add("card-title");
            Label value = new Label("0");
            value.getStyleClass().add("card-value");
            Region gap = new Region();
            HBox.setHgrow(gap, Priority.ALWAYS);
            HBox top = new HBox(10, new VBox(2, title, value), gap, badge);
            top.setAlignment(Pos.TOP_LEFT);
            Sparkline spark = new Sparkline(cls, 180, 34);
            spark.setMaxWidth(Double.MAX_VALUE);
            Label trend = new Label("0 in the last 24 h");
            trend.getStyleClass().add("card-sub");
            VBox card = new VBox(8, top, spark, trend);
            card.getStyleClass().addAll("card", cls);
            HBox.setHgrow(card, Priority.ALWAYS);
            card.setMaxWidth(Double.MAX_VALUE);
            cards.put(sev, card);
            cardValues.put(sev, value);
            cardTrend.put(sev, trend);
            sparklines.put(sev, spark);
            row.getChildren().add(card);
        }
        return row;
    }

    private HBox chartsRow() {
        CategoryAxis x = new CategoryAxis();
        x.setTickLabelRotation(0);
        NumberAxis y = new NumberAxis();
        y.setMinorTickVisible(false);
        y.setForceZeroInRange(true);
        AreaChart<String, Number> area = new AreaChart<>(x, y);
        timelineChart = area;
        area.setAnimated(false);
        area.setCreateSymbols(false);
        area.setLegendSide(javafx.geometry.Side.TOP);
        for (Severity sev : Severity.values()) {          // LOW, MEDIUM, HIGH, CRITICAL = default-color0..3 in CSS
            XYChart.Series<String, Number> series = new XYChart.Series<>();
            series.setName(sev.name().charAt(0) + sev.name().substring(1).toLowerCase(Locale.ROOT));
            timelineSeries.put(sev, series);
            area.getData().add(series);
        }
        modulePie.setLabelsVisible(false);
        modulePie.setLegendVisible(true);
        modulePie.setLegendSide(javafx.geometry.Side.BOTTOM);
        modulePie.setAnimated(false);
        modulePie.setStartAngle(90);
        Circle hole = new Circle();
        hole.getStyleClass().add("donut-hole");
        hole.radiusProperty().bind(javafx.beans.binding.Bindings.min(modulePie.widthProperty(), modulePie.heightProperty()).multiply(0.2));
        hole.setMouseTransparent(true);
        donutTotal.getStyleClass().add("donut-total");
        Label caption = new Label("active");
        caption.getStyleClass().add("card-sub");
        VBox center = new VBox(-4, donutTotal, caption);
        center.setAlignment(Pos.CENTER);
        center.setMouseTransparent(true);
        StackPane donut = new StackPane(modulePie, hole, center);
        StackPane.setAlignment(hole, Pos.CENTER);
        center.translateYProperty().bind(modulePie.heightProperty().multiply(-0.06));
        hole.translateYProperty().bind(modulePie.heightProperty().multiply(-0.06));

        VBox left = Ui.panel(Ui.section("FINDINGS OVER TIME"), area);
        VBox right = Ui.panel(Ui.section("BY MODULE"), donut);
        VBox.setVgrow(area, Priority.ALWAYS);
        VBox.setVgrow(donut, Priority.ALWAYS);
        HBox.setHgrow(left, Priority.ALWAYS);
        left.setPrefHeight(320);
        right.setPrefHeight(320);
        right.setPrefWidth(340);
        right.setMinWidth(300);
        return new HBox(16, left, right);
    }

    private HBox bottomRow() {
        TableView<Finding> table = new TableView<>(rows);
        table.getColumns().add(Ui.column("Time", 130, f -> TIME.format(f.timestamp())));
        TableColumn<Finding, String> sev = Ui.column("Severity", 100, f -> f.severity().name());
        sev.setCellFactory(c -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                getStyleClass().removeIf(s -> s.startsWith("sev-") || s.equals("sev-pill"));
                setText(empty ? null : item);
                if (!empty && item != null) {
                    getStyleClass().addAll("sev-pill", "sev-" + item.toLowerCase(Locale.ROOT));
                }
            }
        });
        table.getColumns().add(sev);
        table.getColumns().add(Ui.column("Rule", 80, Finding::ruleId));
        table.getColumns().add(Ui.column("Target", 160, f -> SafeText.target(f.target())));
        table.getColumns().add(Ui.column("What happened", 440, f -> SafeText.shorten(f.description())));
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.setRowFactory(t -> new TableRow<>() {
            @Override
            protected void updateItem(Finding f, boolean empty) {
                super.updateItem(f, empty);
                getStyleClass().removeIf(s -> s.startsWith("sev-"));
                if (!empty && f != null && f.severity().ordinal() >= Severity.HIGH.ordinal()) {
                    getStyleClass().add("sev-" + f.severity().name().toLowerCase(Locale.ROOT));
                }
            }
        });
        table.setPlaceholder(new Label("No findings yet. Try Scan > Replay log... with sample-data/auth.log"));
        table.setPrefHeight(340);
        attackers.setPlaceholder(new Label("Nobody yet"));
        attackers.setPrefHeight(340);
        VBox feed = Ui.panel(Ui.section("LIVE FINDINGS"), table);
        VBox top = Ui.panel(Ui.section("TOP ATTACKERS"), attackers);
        HBox.setHgrow(feed, Priority.ALWAYS);
        top.setPrefWidth(340);
        top.setMinWidth(300);
        return new HBox(16, feed, top);
    }

    private HBox statusBar() {
        HBox bar = new HBox();
        bar.getStyleClass().add("status-bar");
        bar.setAlignment(Pos.CENTER_LEFT);
        for (int i = 0; i < 5; i++) {               // database, AI, monitors, findings, threat feeds
            Label l = new Label("…");
            statusLabels.add(l);
            bar.getChildren().add(l);
        }
        return bar;
    }

    /** CRITICAL alert: pulse the card (scale + fade) and spin the logo once (rotate). Transforms and transitions. */
    private void alarm() {
        VBox card = cards.get(Severity.CRITICAL);
        ScaleTransition grow = new ScaleTransition(Duration.millis(220), card);
        grow.setToX(1.05);
        grow.setToY(1.05);
        grow.setAutoReverse(true);
        grow.setCycleCount(6);
        FadeTransition blink = new FadeTransition(Duration.millis(220), card);
        blink.setFromValue(1.0);
        blink.setToValue(0.55);
        blink.setAutoReverse(true);
        blink.setCycleCount(6);
        new ParallelTransition(grow, blink).play();
        if (spinner != null) {
            RotateTransition spin = new RotateTransition(Duration.millis(900), spinner);
            spin.setByAngle(360);
            spin.setInterpolator(Interpolator.EASE_BOTH);
            spin.play();
        }
    }
}
