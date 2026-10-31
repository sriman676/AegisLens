package com.aegislens.intrusion;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Identifies a log file by the SHA-256 of its first bytes (up to 256), stored as "length:hash". A rotated or replaced
 * file starts with different bytes, so its fingerprint differs; a file that only grew keeps the same first bytes.
 * While a file is still shorter than 256 bytes the fingerprint covers what exists, and is extended later.
 */
record Fingerprint(int length, String hash) {

    static final int MAX_BYTES = 256;

    /** The fingerprint of the file's current first bytes, or empty if the file does not exist. */
    static Optional<Fingerprint> of(Path file) throws IOException {
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            return Optional.of(of(ch, (int) Math.min(MAX_BYTES, ch.size())));
        } catch (NoSuchFileException e) {
            return Optional.empty();
        }
    }

    static Fingerprint of(FileChannel ch, int length) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(length);
        while (buf.hasRemaining() && ch.read(buf, buf.position()) > 0) {
            // keep reading until the first `length` bytes are in
        }
        return new Fingerprint(buf.position(), sha256(buf.array(), buf.position()));
    }

    /** True if the file at path still starts with the bytes this fingerprint was made from. */
    boolean matches(Path file) throws IOException {
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            return ch.size() >= length && of(ch, length).equals(this);
        } catch (NoSuchFileException e) {
            return false;
        }
    }

    static Optional<Fingerprint> parse(String text) {
        int colon = text == null ? -1 : text.indexOf(':');
        if (colon < 1) {
            return Optional.empty();
        }
        try {
            return Optional.of(new Fingerprint(Integer.parseInt(text.substring(0, colon)), text.substring(colon + 1)));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    @Override
    public String toString() {
        return length + ":" + hash;
    }

    private static String sha256(byte[] bytes, int len) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytes, 0, len);
            return HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is always available", e);
        }
    }
}
