package com.aegislens.ui;

import com.aegislens.app.HeadlessMain;
import javafx.application.Application;

import java.awt.GraphicsEnvironment;
import java.util.Arrays;

/**
 * Real entry point for the fat JAR. It must NOT extend Application, otherwise
 * "JavaFX runtime components are missing" appears when running with java -jar.
 * With --headless, --version or --check-config, or on a machine without a display (a server), it starts HeadlessMain
 * instead and never touches JavaFX.
 */
public final class Launcher {

    private Launcher() {
    }

    public static void main(String[] args) {
        if (wantsHeadless(args) || GraphicsEnvironment.isHeadless()) {
            HeadlessMain.main(args);
        } else {
            Application.launch(AegisLensApp.class, args);
        }
    }

    public static boolean wantsHeadless(String[] args) {
        return Arrays.stream(args).anyMatch(a -> a.equals("--headless") || a.equals("--version") || a.equals("--check-config"));
    }
}
