package com.aegislens.intrusion;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Turns chunks of bytes into complete text lines. A line longer than maxBytes is never held in memory: the rest of it
 * is skipped up to the next newline and counted. A partial last line waits for more bytes (the tailer keeps it until
 * its newline arrives). Invalid UTF-8 becomes U+FFFD instead of an exception.
 */
final class LineSplitter {

    private final int maxBytes;
    private final ByteArrayOutputStream partial = new ByteArrayOutputStream();
    private boolean skipping;
    private long overlong;

    LineSplitter(int maxBytes) {
        this.maxBytes = maxBytes;
    }

    /** Feeds len bytes and returns the lines they completed (without \n or \r\n). */
    List<String> feed(byte[] buf, int len) {
        List<String> lines = new ArrayList<>();
        for (int i = 0; i < len; i++) {
            byte b = buf[i];
            if (b == '\n') {
                if (skipping) {
                    skipping = false;
                    overlong++;
                } else {
                    lines.add(take());
                }
            } else if (!skipping) {
                if (partial.size() >= maxBytes) {
                    skipping = true;               // too long: drop what we have and ignore the rest of this line
                    partial.reset();
                } else {
                    partial.write(b);
                }
            }
        }
        return lines;
    }

    /** At the end of a file: the last line if it had no newline. */
    Optional<String> flush() {
        if (skipping) {
            skipping = false;
            overlong++;
            return Optional.empty();
        }
        return partial.size() == 0 ? Optional.empty() : Optional.of(take());
    }

    /** Bytes of an unfinished line held in memory (the tailer subtracts them from the saved offset). */
    int pendingBytes() {
        return skipping ? 0 : partial.size();
    }

    long overlongLines() {
        return overlong;
    }

    /** Forgets any partial line (after a rotation). */
    void reset() {
        partial.reset();
        skipping = false;
    }

    private String take() {
        String line = partial.toString(StandardCharsets.UTF_8);
        partial.reset();
        return line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
    }
}
