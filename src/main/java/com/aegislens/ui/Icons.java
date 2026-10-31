package com.aegislens.ui;

import javafx.scene.Group;
import javafx.scene.Node;
import javafx.scene.layout.StackPane;
import javafx.scene.shape.SVGPath;

/**
 * Small vector icons drawn with SVGPath on a 24 x 24 grid, so they stay sharp at any size and take their colour from
 * the theme's CSS (style class "icon"). No image files or icon-font licences needed.
 */
public final class Icons {

    public static final String DASHBOARD = "M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z";
    public static final String MALWARE = "M12 2a5 5 0 0 1 5 5v1h2v2h-2v2h3v2h-3v1a5 5 0 0 1-10 0v-1H4v-2h3v-2H5V8h2V7a5 5 0 0 1 5-5zm-1 7v8h2V9z";
    public static final String INTRUSION = "M12 2l9 4v6c0 5-3.8 9.4-9 10-5.2-.6-9-5-9-10V6zm0 4a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm-4 10h8c0-2.2-1.8-4-4-4s-4 1.8-4 4z";
    public static final String WEB = "M12 2a10 10 0 1 1 0 20 10 10 0 0 1 0-20zm0 2c-1.3 1.6-2.2 4-2.4 7h4.8c-.2-3-1.1-5.4-2.4-7zM4.1 11h3.5c.1-2.5.7-4.7 1.7-6.4A8 8 0 0 0 4.1 11zm0 2a8 8 0 0 0 5.2 6.4c-1-1.7-1.6-3.9-1.7-6.4zm5.5 0c.2 3 1.1 5.4 2.4 7 1.3-1.6 2.2-4 2.4-7zm6.8 0c-.1 2.5-.7 4.7-1.7 6.4a8 8 0 0 0 5.2-6.4zm0-2h3.5a8 8 0 0 0-5.2-6.4c1 1.7 1.6 3.9 1.7 6.4z";
    public static final String FINDINGS = "M4 5h2v2H4zM8 5h12v2H8zM4 11h2v2H4zM8 11h12v2H8zM4 17h2v2H4zM8 17h12v2H8z";
    public static final String AI = "M12 2l1.8 5.2L19 9l-5.2 1.8L12 16l-1.8-5.2L5 9l5.2-1.8zM19 14l.9 2.1L22 17l-2.1.9L19 20l-.9-2.1L16 17l2.1-.9zM5 15l.7 1.6 1.6.7-1.6.7L5 19.6l-.7-1.6-1.6-.7 1.6-.7z";
    public static final String CRITICAL = "M12 2L1 21h22zm-1 7h2v6h-2zm0 8h2v2h-2z";
    public static final String HIGH = "M12 2a10 10 0 1 1 0 20 10 10 0 0 1 0-20zm-1 5v7h2V7zm0 9v2h2v-2z";
    public static final String MEDIUM = "M12 2l8 3.5V11c0 5-3.4 9.3-8 10.5C7.4 20.3 4 16 4 11V5.5zm-1 6v5h2V8zm0 7v2h2v-2z";
    public static final String LOW = "M12 2a10 10 0 1 1 0 20 10 10 0 0 1 0-20zm-1 8v7h2v-7zm0-3v2h2V7z";
    public static final String SUN = "M12 7a5 5 0 1 1 0 10 5 5 0 0 1 0-10zM11 1h2v3h-2zM11 20h2v3h-2zM1 11h3v2H1zM20 11h3v2h-3zM4.2 5.6l1.4-1.4 2.1 2.1-1.4 1.4zM16.3 17.7l1.4-1.4 2.1 2.1-1.4 1.4zM4.2 18.4l2.1-2.1 1.4 1.4-2.1 2.1zM16.3 6.3l2.1-2.1 1.4 1.4-2.1 2.1z";
    public static final String REPORTS = "M4 20h16v2H4zM6 10h3v8H6zM11 5h3v13h-3zM16 13h3v5h-3z";
    public static final String SQL = "M12 2c4.4 0 8 1.3 8 3v14c0 1.7-3.6 3-8 3s-8-1.3-8-3V5c0-1.7 3.6-3 8-3zm6 5.3C16.5 8.1 14.4 8.5 12 8.5S7.5 8.1 6 7.3V10c0 .6 2.4 1.8 6 1.8s6-1.2 6-1.8zm0 5c-1.5.8-3.6 1.2-6 1.2s-4.5-.4-6-1.2V15c0 .6 2.4 1.8 6 1.8s6-1.2 6-1.8z";
    public static final String INTEL = "M12 2l8 3v6c0 5.2-3.4 9.8-8 11-4.6-1.2-8-5.8-8-11V5zm0 5a3 3 0 1 0 0 6 3 3 0 0 0 0-6zm-6 1v2h2V8zm10 0v2h2V8z";
    public static final String SETTINGS = "M10.3 2h3.4l.5 2.6 1.9.8 2.2-1.5 2.4 2.4-1.5 2.2.8 1.9 2.6.5v3.4l-2.6.5-.8 1.9 1.5 2.2-2.4 2.4-2.2-1.5-1.9.8-.5 2.6h-3.4l-.5-2.6-1.9-.8-2.2 1.5-2.4-2.4 1.5-2.2-.8-1.9L1 13.7v-3.4l2.6-.5.8-1.9-1.5-2.2 2.4-2.4 2.2 1.5 1.9-.8zM12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z";
    public static final String SANDBOX = "M3 3h18v4H3zM5 9h14v12H5zm3 3v6h2v-6zm6 0v6h2v-6z";
    public static final String MOON = "M14.5 2A9 9 0 1 0 22 14.5 7 7 0 0 1 14.5 2z";

    private Icons() {
    }

    /** An icon of the given size (pixels), coloured by CSS through the "icon" style class plus extra classes. */
    public static Node icon(String path, double size, String... styleClasses) {
        SVGPath p = new SVGPath();
        p.setContent(path);
        p.getStyleClass().add("icon");
        p.getStyleClass().addAll(styleClasses);
        p.setScaleX(size / 24.0);                 // scale transform from the 24 x 24 grid
        p.setScaleY(size / 24.0);
        StackPane box = new StackPane(new Group(p));    // Group: the scaled size counts for layout
        box.setMinSize(size, size);
        box.setPrefSize(size, size);
        box.setMaxSize(size, size);
        return box;
    }
}
