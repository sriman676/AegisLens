package com.aegislens.app;

import com.aegislens.core.Finding;
import com.aegislens.util.CidrSet;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Trusted addresses and users whose findings are dropped (alert-fatigue control).
 * Entries, comma separated: an IPv4 or IPv6 address, a CIDR range (10.0.0.0/8, 2001:db8::/32) or user:name.
 * Only IP literals are parsed (never a DNS lookup), so a hostname in the list or in a finding is simply ignored.
 */
public final class AllowList {

    /** The setting key that holds the list. */
    public static final String SETTING = "allowlist";
    public static final String USER_PREFIX = "user:";
    /** The evidence key a detector uses for a user name. */
    public static final String USER_EVIDENCE = "user";

    private static final Logger LOG = Logger.getLogger(AllowList.class.getName());

    private final CidrSet networks = new CidrSet();
    private final Set<String> users = new HashSet<>();

    /** Parses a comma-separated list; bad entries are skipped and logged. */
    public static AllowList parse(String text) {
        AllowList list = new AllowList();
        if (text == null) {
            return list;
        }
        for (String raw : text.split(",")) {
            String entry = raw.trim();
            if (!entry.isEmpty() && !list.add(entry)) {
                LOG.warning("Ignoring allow-list entry that is not an IP, CIDR or user:name: " + entry);
            }
        }
        return list;
    }

    /** The entries parse() would skip, so the Settings view can name them instead of dropping them silently. */
    public static List<String> invalidEntries(String text) {
        List<String> bad = new ArrayList<>();
        for (String raw : text == null ? new String[0] : text.split(",")) {
            String entry = raw.trim();
            if (!entry.isEmpty() && !new AllowList().add(entry)) {       // a fresh list: a repeated entry is not "invalid"
                bad.add(entry);
            }
        }
        return bad;
    }

    private boolean add(String entry) {
        if (entry.startsWith(USER_PREFIX)) {
            return entry.length() > USER_PREFIX.length() && users.add(entry.substring(USER_PREFIX.length()));
        }
        return networks.add(entry);
    }

    /** True if the finding's target is a trusted address or its evidence names a trusted user. */
    public boolean isTrusted(Finding f) {
        String user = f.evidence().get(USER_EVIDENCE);
        return (user != null && users.contains(user)) || networks.contains(f.target());
    }

    public int size() {
        return networks.size() + users.size();
    }
}
