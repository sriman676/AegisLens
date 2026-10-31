package com.aegislens.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A set of IPv4/IPv6 addresses and CIDR ranges with fast lookups: ranges are grouped by prefix length, so a lookup
 * costs one hash check per distinct prefix length, even with tens of thousands of feed entries.
 * Only IP literals are accepted: a host name is never resolved, so no DNS lookup can happen.
 */
public final class CidrSet {

    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
    private static final Pattern IPV6 = Pattern.compile("[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*");
    private static final HexFormat HEX = HexFormat.of();

    /** prefix length -> masked network addresses (hex, with a "4:" or "6:" family tag). */
    private final Map<Integer, Set<String>> byPrefix = new HashMap<>();
    private int size;

    /** Adds "1.2.3.4", "10.0.0.0/8", "2001:db8::/32" and so on. Returns false (and adds nothing) for anything else. */
    public boolean add(String entry) {
        if (entry == null) {
            return false;
        }
        String text = entry.trim();
        int slash = text.indexOf('/');
        Optional<InetAddress> ip = literal(slash < 0 ? text : text.substring(0, slash));
        if (ip.isEmpty()) {
            return false;
        }
        byte[] bytes = ip.get().getAddress();
        int bits = bytes.length * 8;
        if (slash >= 0) {
            try {
                bits = Integer.parseInt(text.substring(slash + 1));
            } catch (NumberFormatException e) {
                return false;
            }
        }
        if (bits < 0 || bits > bytes.length * 8) {
            return false;
        }
        if (byPrefix.computeIfAbsent(bits, k -> new HashSet<>()).add(key(bytes, bits))) {
            size++;
        }
        return true;
    }

    /** True if the text is an IP literal inside one of the ranges. */
    public boolean contains(String ip) {
        Optional<InetAddress> address = literal(ip);
        return address.isPresent() && contains(address.get().getAddress());
    }

    /** True if the raw address (4 or 16 bytes) is inside one of the ranges. IPv4 never matches IPv6 ranges. */
    public boolean contains(byte[] address) {
        for (Map.Entry<Integer, Set<String>> e : byPrefix.entrySet()) {
            if (e.getKey() <= address.length * 8 && e.getValue().contains(key(address, e.getKey()))) {
                return true;
            }
        }
        return false;
    }

    public int size() {
        return size;
    }

    /** Parses an IP literal; anything not shaped like one returns empty, so InetAddress never does a DNS lookup. */
    public static Optional<InetAddress> literal(String text) {
        if (text == null || !(IPV4.matcher(text).matches() || IPV6.matcher(text).matches())) {
            return Optional.empty();
        }
        try {
            return Optional.of(InetAddress.getByName(text));
        } catch (UnknownHostException e) {
            return Optional.empty();               // for example 999.1.1.1
        }
    }

    /** The first bits of address, other bits zeroed, as text tagged with the address family. */
    private static String key(byte[] address, int bits) {
        byte[] masked = new byte[address.length];
        int full = bits / 8;
        System.arraycopy(address, 0, masked, 0, full);
        int rest = bits % 8;
        if (rest > 0) {
            masked[full] = (byte) (address[full] & (0xFF << (8 - rest)));
        }
        return (address.length == 4 ? "4:" : "6:") + HEX.formatHex(masked);
    }
}
