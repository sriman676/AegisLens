package com.aegislens.ui;

import com.aegislens.app.AnalystActions;

import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * The commands of the AWT Analyst Console, without any AWT so they are unit-tested: parse one typed line and run it
 * through AnalystActions (the same actions as the Findings view).
 */
public final class ConsoleCommands {

    /** Longest wait for an AI explanation before the console gives up (the offline fallback answers much sooner). */
    public static final int EXPLAIN_TIMEOUT_SECONDS = 60;
    public static final String HELP = """
            Commands:
              block <ip>     record a public IP as blocked (exported later; the firewall is never changed)
              trust <ip|cidr> add to the allow-list (new findings for it are dropped)
              fp <id>        mark finding <id> as a false positive
              explain <id>   explain finding <id> (cloud, local or offline)
              help           this text
            Keys: Enter runs, Up/Down walk the history, Esc clears the line.""";

    /** One parsed line: the verb (lower case) and its argument (may be empty). */
    public record Command(String verb, String arg) {
    }

    private ConsoleCommands() {
    }

    /** Splits "block 203.0.113.9" into verb and argument; empty for a blank line. */
    public static Optional<Command> parse(String line) {
        if (line == null || line.isBlank()) {
            return Optional.empty();
        }
        String[] parts = line.strip().split("\\s+", 2);
        return Optional.of(new Command(parts[0].toLowerCase(Locale.ROOT), parts.length > 1 ? parts[1].strip() : ""));
    }

    /** Runs a command and returns the text to print. Never throws: problems come back as readable lines. */
    public static String run(Command c, AnalystActions actions) {
        try {
            return switch (c.verb()) {
                case "help", "?" -> HELP;
                case "block" -> actions.recordBlock(required(c), "analyst console");
                case "trust" -> actions.trust(required(c));
                case "fp" -> actions.falsePositive(id(c));
                case "explain" -> actions.explain(id(c)).get(EXPLAIN_TIMEOUT_SECONDS, TimeUnit.SECONDS).text();
                default -> "Unknown command '" + SafeText.shorten(c.verb()) + "'. Type help.";
            };
        } catch (AnalystActions.RefusedException | IllegalArgumentException e) {
            return "Refused: " + e.getMessage();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Interrupted.";
        } catch (Exception e) {
            return "Failed: " + SafeText.shorten(e.getMessage());
        }
    }

    private static String required(Command c) {
        if (c.arg().isEmpty()) {
            throw new IllegalArgumentException(c.verb() + " needs an argument; type help.");
        }
        return c.arg();
    }

    private static long id(Command c) {
        try {
            return Long.parseLong(required(c));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("'" + SafeText.shorten(c.arg()) + "' is not a finding id (a number).");
        }
    }
}
