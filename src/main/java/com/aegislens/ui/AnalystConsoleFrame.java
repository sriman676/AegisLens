package com.aegislens.ui;

import com.aegislens.app.AnalystActions;

import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.Color;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Label;
import java.awt.Panel;
import java.awt.TextArea;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.LinkedList;
import java.util.ListIterator;

/**
 * The Analyst Console: a small AWT window (Tools > Analyst Console) for keyboard-driven analysts. Type a command such as
 * "block 203.0.113.9" or "fp 42" and press Enter. It runs the same AnalystActions as the JavaFX Findings view.
 * Event handling uses the AWT delegation model: an ActionListener (buttons and Enter), a KeyAdapter (history and Esc)
 * and a WindowAdapter (closing only hides this window, never the app). Commands run on a worker thread; the output is
 * appended on the AWT event thread with EventQueue.invokeLater.
 * Known limitation: AWT next to JavaFX is not tested on macOS.
 */
public final class AnalystConsoleFrame extends Frame {

    /** Commands remembered for Up/Down. */
    public static final int HISTORY = 50;
    private static AnalystConsoleFrame open;          // one console at a time, guarded by the AWT event thread

    private final AnalystActions actions;
    private final TextArea output = new TextArea("", 18, 90, TextArea.SCROLLBARS_VERTICAL_ONLY);
    private final TextField input = new TextField(60);
    private final Label status = new Label("Type help and press Enter.");
    private final LinkedList<String> history = new LinkedList<>();
    private ListIterator<String> cursor = history.listIterator();

    private AnalystConsoleFrame(AnalystActions actions) {
        super("AegisLens Analyst Console");
        this.actions = actions;
        output.setEditable(false);
        output.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        output.setBackground(new Color(15, 23, 42));
        output.setForeground(new Color(226, 232, 240));
        input.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 14));

        ActionListener runListener = e -> runLine();             // lambda form of an ActionListener
        input.addActionListener(runListener);                    // Enter in a TextField fires an ActionEvent
        input.addKeyListener(new HistoryKeys());
        Button run = new Button("Run");
        run.addActionListener(runListener);
        Button help = new Button("Help");
        help.setActionCommand("help");
        help.addActionListener(new TemplateListener());          // named class form of an ActionListener
        Button block = new Button("Block IP...");
        block.setActionCommand("block ");
        block.addActionListener(new TemplateListener());
        Button fp = new Button("False positive...");
        fp.setActionCommand("fp ");
        fp.addActionListener(new TemplateListener());
        Button explain = new Button("Explain...");
        explain.setActionCommand("explain ");
        explain.addActionListener(new TemplateListener());

        Panel buttons = new Panel();
        for (Button b : new Button[] {run, help, block, fp, explain}) {
            buttons.add(b);
        }
        Panel bottom = new Panel(new BorderLayout(6, 6));
        bottom.add(input, BorderLayout.CENTER);
        bottom.add(buttons, BorderLayout.EAST);
        bottom.add(status, BorderLayout.SOUTH);
        add(output, BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);
        addWindowListener(new Closer());
        pack();
        print(ConsoleCommands.HELP);
    }

    /** Opens the console, or brings the open one to the front. Safe to call from any thread. */
    public static void showFor(AnalystActions actions) {
        EventQueue.invokeLater(() -> {
            if (open == null) {
                open = new AnalystConsoleFrame(actions);
                open.setLocationByPlatform(true);
            }
            open.setVisible(true);
            open.toFront();
        });
    }

    /** Parses the line, runs it on a worker thread (never block the AWT event thread) and prints the answer. */
    private void runLine() {
        String line = input.getText();
        ConsoleCommands.parse(line).ifPresent(command -> {
            remember(line.strip());
            input.setText("");
            print("> " + line.strip());
            status.setText("Running " + command.verb() + "…");
            Thread worker = new Thread(() -> {
                String answer = ConsoleCommands.run(command, actions);
                EventQueue.invokeLater(() -> {
                    print(answer);
                    status.setText("Ready.");
                });
            }, "aegislens-console");
            worker.setDaemon(true);
            worker.start();
        });
    }

    private void remember(String line) {
        history.remove(line);
        history.addFirst(line);
        if (history.size() > HISTORY) {
            history.removeLast();
        }
        cursor = history.listIterator();
    }

    private void print(String text) {
        output.append(text + "\n\n");
    }

    /** Buttons put a command template into the input line; "help" runs at once. */
    private final class TemplateListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            input.setText(e.getActionCommand());
            input.requestFocus();
            input.setCaretPosition(input.getText().length());
            if (e.getActionCommand().equals("help")) {
                runLine();
            }
        }
    }

    /** Up/Down walk the command history, Esc clears the line (KeyAdapter: only the methods we need). */
    private final class HistoryKeys extends KeyAdapter {
        @Override
        public void keyPressed(KeyEvent e) {
            switch (e.getKeyCode()) {
                case KeyEvent.VK_UP -> {
                    if (cursor.hasNext()) {
                        input.setText(cursor.next());
                    }
                }
                case KeyEvent.VK_DOWN -> input.setText(cursor.hasPrevious() ? cursor.previous() : "");
                case KeyEvent.VK_ESCAPE -> input.setText("");
                default -> { }
            }
        }
    }

    /** Closing the console only hides it; the main window and the monitors keep running (WindowAdapter). */
    private final class Closer extends WindowAdapter {
        @Override
        public void windowClosing(WindowEvent e) {
            setVisible(false);
        }

        @Override
        public void windowOpened(WindowEvent e) {
            input.requestFocus();
        }
    }
}
