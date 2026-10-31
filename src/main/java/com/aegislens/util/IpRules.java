package com.aegislens.util;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Optional;

/**
 * Decides whether an address may be blocked: only a routable public IP literal. Private, loopback, link-local,
 * "any", multicast and IPv6 unique-local (fc00::/7) addresses are refused, because blocking them could cut the admin
 * off their own network. Parsing goes through CidrSet.literal, so there is never a DNS lookup.
 */
public final class IpRules {

    private IpRules() {
    }

    /** Why this text cannot be blocked, or empty if it is a public IP literal. */
    public static Optional<String> whyNotBlockable(String text) {
        Optional<InetAddress> parsed = CidrSet.literal(text == null ? null : text.strip());
        if (parsed.isEmpty()) {
            return Optional.of("'" + text + "' is not an IP address");
        }
        InetAddress ip = parsed.get();
        boolean uniqueLocal6 = ip instanceof Inet6Address && (ip.getAddress()[0] & 0xFE) == 0xFC;
        if (ip.isLoopbackAddress() || ip.isSiteLocalAddress() || ip.isLinkLocalAddress() || ip.isAnyLocalAddress()
                || ip.isMulticastAddress() || uniqueLocal6) {
            return Optional.of(ip.getHostAddress() + " is a private, local or multicast address");
        }
        return Optional.empty();
    }

    /** The canonical form ("2001:db8:0:0:0:0:0:1") of a blockable address; call whyNotBlockable first. */
    public static InetAddress blockable(String text) {
        if (whyNotBlockable(text).isPresent()) {
            throw new IllegalArgumentException(whyNotBlockable(text).get());
        }
        return CidrSet.literal(text.strip()).orElseThrow();
    }
}
