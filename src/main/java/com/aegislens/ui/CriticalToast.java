package com.aegislens.ui;

import com.aegislens.core.Finding;
import com.aegislens.core.Severity;
import javafx.animation.FadeTransition;
import javafx.animation.PauseTransition;
import javafx.animation.SequentialTransition;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;
import javafx.stage.Popup;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * A small notice in the bottom-right corner of the window when a new CRITICAL finding arrives, so the
 * analyst sees it on any screen. Many CRITICAL findings at once become one notice ("5 new CRITICAL findings"); the
 * setting {@link #SETTING} = "false" turns it off (do not disturb). Clicking the notice closes it.
 */
final class CriticalToast {

    /** Settings key; anything but "false" means notices are shown. */
    static final String SETTING = "ui.notify.critical";
    static final Duration VISIBLE = Duration.seconds(6);
    private static final double WIDTH = 380;
    private static final double MARGIN = 24;

    private final Stage owner;
    private final Popup popup = new Popup();
    private final VBox box;
    private final Label text = new Label();
    private final AtomicInteger waiting = new AtomicInteger();
    private final LiveRefresh showSoon = new LiveRefresh(this::showNow);
    private volatile Finding latest;
    private volatile boolean enabled = true;
    private SequentialTransition running;

    CriticalToast(Stage owner) {
        this.owner = owner;
        Label title = new Label("CRITICAL");
        title.getStyleClass().add("toast-title");
        text.setWrapText(true);
        text.getStyleClass().add("toast-text");
        box = new VBox(4, title, text);
        box.getStyleClass().addAll("root", "toast");   // "root" so the design's colour variables apply in the popup
        box.setPrefWidth(WIDTH);
        box.setMaxWidth(WIDTH);                         // long text wraps instead of widening the notice
        box.setOnMouseClicked(e -> hide());
        popup.getContent().add(box);
    }

    /** Turns the notices on or off (Settings > Appearance). */
    void setEnabled(boolean on) {
        enabled = on;
    }

    /** Any thread: a finding was saved; only CRITICAL ones are shown. */
    void offer(Finding f) {
        if (enabled && f.severity() == Severity.CRITICAL) {
            latest = f;
            waiting.incrementAndGet();
            showSoon.poke();
        }
    }

    /** "New CRITICAL finding: NET-001 on 203.0.113.45 ..." or "3 new CRITICAL findings, latest: ...". */
    static String message(int count, Finding f) {
        String what = f.ruleId() + " on " + SafeText.target(f.target()) + ": " + f.description();
        return SafeText.shorten(count == 1 ? "New CRITICAL finding: " + what : count + " new CRITICAL findings, latest: " + what);
    }

    private void showNow() {
        int count = waiting.getAndSet(0);
        if (count == 0 || !owner.isShowing()) {
            return;
        }
        text.setText(message(count, latest));
        box.setAccessibleText(text.getText());
        box.getStylesheets().setAll(owner.getScene().getStylesheets());
        box.setStyle(owner.getScene().getRoot().getStyle());          // the user's accent colour and text size
        if (running != null) {
            running.stop();
        }
        popup.show(owner, owner.getX() + owner.getWidth() - WIDTH - MARGIN, owner.getY() + owner.getHeight());
        popup.setX(owner.getX() + owner.getWidth() - popup.getWidth() - MARGIN);   // its size (shadow included) is
        popup.setY(owner.getY() + owner.getHeight() - popup.getHeight() - MARGIN); // known once it is shown
        FadeTransition in = new FadeTransition(Duration.millis(250), box);
        in.setFromValue(0);
        in.setToValue(1);
        FadeTransition out = new FadeTransition(Duration.millis(400), box);
        out.setToValue(0);
        running = new SequentialTransition(in, new PauseTransition(VISIBLE), out);
        running.setOnFinished(e -> popup.hide());
        running.play();
    }

    private void hide() {
        if (running != null) {
            running.stop();
        }
        popup.hide();
    }
}
