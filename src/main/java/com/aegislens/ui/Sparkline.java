package com.aegislens.ui;

import javafx.scene.layout.Pane;
import javafx.scene.shape.Polygon;
import javafx.scene.shape.Polyline;

/**
 * A tiny trend line (no axes) for a severity card: the last 24 hourly counts, scaled to fit, with a soft fill below.
 * Colour comes from CSS ("sparkline-line" / "sparkline-fill" plus the severity class).
 */
public final class Sparkline extends Pane {

    private final Polyline line = new Polyline();
    private final Polygon fill = new Polygon();
    private int[] values = new int[0];

    public Sparkline(String severityClass, double width, double height) {
        line.getStyleClass().addAll("sparkline-line", severityClass);
        fill.getStyleClass().addAll("sparkline-fill", severityClass);
        getChildren().addAll(fill, line);
        setPrefSize(width, height);
        setMinSize(width, height);
        setMaxHeight(height);
    }

    public void setValues(int[] newValues) {
        this.values = newValues == null ? new int[0] : newValues.clone();
        requestLayout();
    }

    @Override
    protected void layoutChildren() {
        line.getPoints().clear();
        fill.getPoints().clear();
        double w = getWidth();
        double h = getHeight();
        if (values.length < 2 || w <= 0 || h <= 0) {
            return;
        }
        int max = 1;
        for (int v : values) {
            max = Math.max(max, v);
        }
        double pad = 2;
        double step = (w - 2 * pad) / (values.length - 1);
        fill.getPoints().addAll(pad, h);
        for (int i = 0; i < values.length; i++) {
            double x = pad + i * step;
            double y = h - pad - (h - 2 * pad) * values[i] / max;
            line.getPoints().addAll(x, y);
            fill.getPoints().addAll(x, y);
        }
        fill.getPoints().addAll(pad + (values.length - 1) * step, h);
    }
}
