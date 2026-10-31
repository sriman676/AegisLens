package com.aegislens.intrusion;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Follows a growing log file like "tail -F": polls every 500 ms, hands complete lines to a LineConsumer, keeps a partial
 * last line until its newline arrives, skips and counts lines over 8 KB, and survives rotation (the file renamed and a
 * new one created) and copy-truncate (the file emptied in place): it first finishes the old file, then reopens from 0.
 * On start it resumes from the OffsetStore when the saved fingerprint matches, otherwise it starts at the END of the file
 * (or the beginning with startAtBeginning, for replays). The offset is saved after the lines were handed on.
 * Stops via stopTailing(): a volatile flag plus interrupt; the channel is always closed in finally.
 * Polling works the same on every OS and on network/WSL drives, unlike WatchService.
 */
public class LogTailer extends Thread {

    public static final Duration POLL = Duration.ofMillis(500);
    private static final Logger LOG = Logger.getLogger(LogTailer.class.getName());
    private static final int CHUNK = 64 * 1024;

    private final Path file;
    private final LineConsumer consumer;
    private final OffsetStore offsets;
    private final boolean startAtBeginning;
    private final SourceCounters counters;
    private final LineSplitter splitter = new LineSplitter(LogSource.MAX_LINE);
    private volatile boolean running = true;
    private volatile boolean caughtUp;

    public LogTailer(Path file, LineConsumer consumer, OffsetStore offsets, boolean startAtBeginning, SourceCounters counters) {
        super("aegislens-tail-" + file.getFileName());
        this.file = file.toAbsolutePath().normalize();
        this.consumer = consumer;
        this.offsets = offsets;
        this.startAtBeginning = startAtBeginning;
        this.counters = counters;
        setDaemon(true);
    }

    /** Asks the thread to finish: it leaves its poll loop and closes the file. */
    public void stopTailing() {
        running = false;
        interrupt();
    }

    public Path file() {
        return file;
    }

    public SourceCounters counters() {
        return counters;
    }

    /** True once the tailer has read everything that existed (useful in tests and the status view). */
    public boolean caughtUp() {
        return caughtUp;
    }

    public long overlongLines() {
        return splitter.overlongLines();
    }

    @Override
    public void run() {
        boolean fromStart = false;                         // after a rotation the new file is read from 0
        try {
            while (running) {
                try {
                    fromStart = followUntilRotated(fromStart);
                } catch (NoSuchFileException missing) {
                    fromStart = true;                      // when it appears it is a new file: read all of it
                    sleepPoll();                           // between "rename" and "create" the file may not exist
                } catch (IOException e) {
                    LOG.log(Level.WARNING, "Reading " + file + " failed; retrying", e);
                    sleepPoll();
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();            // asked to stop
        }
    }

    /** Reads one incarnation of the file until it is rotated or truncated. Returns true (read the next one from 0). */
    private boolean followUntilRotated(boolean fromStart) throws IOException, InterruptedException {
        FileChannel ch = FileChannel.open(file, StandardOpenOption.READ);     // outer: the file
        try {
            Fingerprint fp = Fingerprint.of(ch, (int) Math.min(Fingerprint.MAX_BYTES, ch.size()));
            long pos = startPosition(ch, fp, fromStart);
            offsets.save(file, pos, fp.toString());        // remember the start at once, so lines written while
                                                            // AegisLens is closed are read after a restart
            splitter.reset();
            ByteBuffer buf = ByteBuffer.allocate(CHUNK);
            while (running) {
                long size = ch.size();
                if (size > pos) {
                    pos = readFrom(ch, pos, buf);
                    if (fp.length() < Fingerprint.MAX_BYTES && size > fp.length()) {
                        fp = Fingerprint.of(ch, (int) Math.min(Fingerprint.MAX_BYTES, size));   // the file grew past the old prefix
                    }
                    offsets.save(file, pos - splitter.pendingBytes(), fp.toString());
                    continue;
                }
                caughtUp = true;
                if (size < pos || !fp.matches(file)) {
                    LOG.info("Log " + file + " was rotated or truncated; reading the new file from the start");
                    return true;
                }
                sleepPoll();
            }
            return false;
        } finally {
            ch.close();                                     // always, also when interrupted
        }
    }

    private long startPosition(FileChannel ch, Fingerprint fp, boolean fromStart) throws IOException {
        if (fromStart) {
            return 0;
        }
        Optional<OffsetStore.Saved> saved = offsets.load(file);
        if (saved.isPresent()) {
            Optional<Fingerprint> savedFp = Fingerprint.parse(saved.get().fingerprint());
            if (savedFp.isPresent() && savedFp.get().matches(file) && saved.get().offset() <= ch.size()) {
                return saved.get().offset();                // same file as before the restart: continue
            }
        }
        return startAtBeginning ? 0 : ch.size();            // unknown file: only new lines (or all for a replay)
    }

    /** Reads available bytes from pos and passes every completed line on. Returns the new position. */
    private long readFrom(FileChannel ch, long pos, ByteBuffer buf) throws IOException, InterruptedException {
        buf.clear();
        int n = ch.read(buf, pos);
        if (n <= 0) {
            return pos;
        }
        List<String> lines = splitter.feed(buf.array(), n);
        for (String line : lines) {
            counters.lines.incrementAndGet();
            counters.touch(Instant.now());
            consumer.accept(line);                          // inner work per line; parse errors are handled there
        }
        return pos + n;
    }

    private void sleepPoll() throws InterruptedException {
        Thread.sleep(POLL.toMillis());
    }
}
