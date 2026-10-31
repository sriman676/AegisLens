package com.aegislens.ui;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** R15 foundations: window state (G12), message bundle (G14), and every style class present in both designs. */
class ShellFoundationsTest {

    @Test
    void windowStateRoundTripsAndRejectsBrokenValues() {
        WindowState w = new WindowState(120, 80, 1360, 860, true);
        assertEquals(w, WindowState.parse(w.toString()).orElseThrow());
        assertTrue(WindowState.parse(null).isEmpty());
        assertTrue(WindowState.parse("1,2,3").isEmpty());
        assertTrue(WindowState.parse("a,b,c,d,true").isEmpty());
        assertTrue(WindowState.parse("0,0,200,100,false").isEmpty(), "smaller than the minimum window");
        assertTrue(WindowState.parse("NaN,0,1200,800,false").isEmpty());
    }

    @Test
    void messagesFillArgumentsAndShowMissingKeys() {
        assertEquals("Go to Findings", Messages.text("menu.view.goto", Messages.text("nav.Findings")));
        assertEquals("!no.such.key!", Messages.text("no.such.key"));
        assertTrue(Messages.text("close.monitoring", 2).contains("2 source(s)"));
    }

    @Test
    void everyKeyTheCodeUsesExistsInTheBundle() throws IOException {
        Properties bundle = new Properties();
        try (InputStream in = getClass().getResourceAsStream("/i18n/messages.properties")) {
            bundle.load(new java.io.InputStreamReader(in, StandardCharsets.UTF_8));
        }
        Set<String> missing = new TreeSet<>();
        for (String key : found(Pattern.compile("(?:Messages\\.text|item)\\(\"([a-z][\\w.]+)\""))) {
            if (!key.endsWith(".") && !bundle.containsKey(key)) {        // "nav." + name is checked below
                missing.add(key);
            }
        }
        for (String view : found(Pattern.compile("navButton\\(\"(\\w+)\""))) {
            if (!bundle.containsKey("nav." + view)) {
                missing.add("nav." + view);
            }
        }
        assertEquals(Set.of(), missing);
    }

    @Test
    void everyStyleClassUsedInJavaExistsInBothStylesheets() throws IOException {
        String dark = Files.readString(Path.of("src/main/resources/ui/aegislens-dark.css"));
        String light = Files.readString(Path.of("src/main/resources/ui/aegislens-light.css"));
        Set<String> missing = new TreeSet<>();
        for (String cls : found(Pattern.compile("getStyleClass\\(\\)\\.(?:add|addAll)\\(([^)]*)\\)"))) {
            for (Matcher m = Pattern.compile("\"([a-z][a-z0-9-]+)\"").matcher(cls); m.find(); ) {
                String name = "." + m.group(1);
                if (!dark.contains(name)) {
                    missing.add("dark " + name);
                }
                if (!light.contains(name)) {
                    missing.add("light " + name);
                }
            }
        }
        assertEquals(Set.of(), missing);
    }

    /** All first groups of the pattern in the ui sources. */
    private static Set<String> found(Pattern pattern) throws IOException {
        Set<String> all = new TreeSet<>();
        try (Stream<Path> files = Files.list(Path.of("src/main/java/com/aegislens/ui"))) {
            for (Path f : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                Matcher m = pattern.matcher(Files.readString(f));
                while (m.find()) {
                    all.add(m.group(1));
                }
            }
        }
        return all;
    }
}
