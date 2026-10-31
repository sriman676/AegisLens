package com.aegislens.ui;

import com.aegislens.app.AnalystActions;
import com.aegislens.app.AppConfig;
import com.aegislens.app.ScanCoordinator;
import com.aegislens.db.BlockedIpRepository;
import com.aegislens.db.Database;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** The AWT console's commands, tested without a display. */
class ConsoleCommandsTest {

    @Test
    void linesAreParsedIntoVerbAndArgument() {
        assertEquals(new ConsoleCommands.Command("block", "203.0.113.9"), ConsoleCommands.parse("  BLOCK   203.0.113.9 ").orElseThrow());
        assertEquals(new ConsoleCommands.Command("help", ""), ConsoleCommands.parse("help").orElseThrow());
        assertTrue(ConsoleCommands.parse("   ").isEmpty());
    }

    @Test
    void commandsRunThroughAnalystActionsAndNeverThrow() throws Exception {
        try (Database db = Database.inMemory()) {
            ScanCoordinator c = new ScanCoordinator(db, AppConfig.defaults());
            c.start();
            try {
                AnalystActions actions = new AnalystActions(c);
                assertTrue(run("help", actions).contains("block <ip>"));
                assertTrue(run("block 203.0.113.9", actions).startsWith("Recorded"));
                assertTrue(new BlockedIpRepository(db).isBlocked("203.0.113.9"));
                assertTrue(run("block 10.0.0.1", actions).startsWith("Refused"));
                assertTrue(run("block", actions).startsWith("Refused"), "missing argument");
                assertTrue(run("fp abc", actions).contains("not a finding id"));
                assertTrue(run("fp 12345", actions).startsWith("Refused"), "unknown finding");
                assertTrue(run("rm -rf /", actions).startsWith("Unknown command"));
            } finally {
                c.shutdown();
            }
        }
    }

    private static String run(String line, AnalystActions actions) {
        return ConsoleCommands.run(ConsoleCommands.parse(line).orElseThrow(), actions);
    }
}
