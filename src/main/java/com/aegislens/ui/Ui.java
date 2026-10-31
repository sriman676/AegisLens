package com.aegislens.ui;

import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.layout.VBox;

import java.util.function.Function;

/**
 * Small builders shared by every view, so each screen uses the same panel, heading, table column and button styles.
 */
final class Ui {

    /** Text size / 13 px, set by the window before it builds the views, so table columns grow with the text. */
    private static double scale = 1.0;
    /** Columns up to this width (at 13 px) hold short values and keep their full width. */
    private static final double SHORT_COLUMN = 130;

    private Ui() {
    }

    /** Called on the FX thread before the views are (re)built. */
    static void setScale(int fontSize) {
        scale = fontSize / (double) Appearance.DEFAULT_FONT;
    }

    /** A rounded card ("panel" style class) stacking its children. */
    static VBox panel(Node... children) {
        VBox box = new VBox(10, children);
        box.getStyleClass().add("panel");
        return box;
    }

    /** The big title and grey subtitle at the top of a view. */
    static VBox header(String title, String subtitle) {
        Label t = new Label(title);
        t.getStyleClass().add("page-title");
        Label s = new Label(subtitle);
        s.getStyleClass().add("page-subtitle");
        return new VBox(2, t, s);
    }

    /** A small upper-case heading inside a panel. */
    static Label section(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("section-title");
        return l;
    }

    /** A read-only text column of a TableView over rows of type R. */
    static <R> TableColumn<R, String> column(String name, double width, Function<R, String> value) {
        TableColumn<R, String> c = new TableColumn<>(name);
        c.setPrefWidth(width * scale);
        if (width <= SHORT_COLUMN) {
            c.setMinWidth(width * scale);              // codes, times and numbers are never cut; long text gives way
        }
        c.setCellValueFactory(cell -> new ReadOnlyStringWrapper(value.apply(cell.getValue())));
        return c;
    }

    /** A button with one style class and an action. */
    static Button button(String text, String styleClass, Runnable action) {
        Button b = new Button(text);
        b.getStyleClass().add(styleClass);
        b.setOnAction(e -> action.run());
        return b;
    }
}
