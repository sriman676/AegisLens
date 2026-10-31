package com.aegislens.intrusion;

import com.aegislens.core.Finding;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Sysmon events 3 and 22: HOST-005 a connection to or from an address on a threat list; HOST-006 a DNS lookup of a
 * domain on a threat list, or of a look-alike of a known brand. The lists and the look-alike check are passed in by
 * the app (this package never touches the database or the web package).
 */
public class HostNetworkDetector extends HostDetector {

    public static final String ADDRESS_RULE = "HOST-005";
    public static final String DOMAIN_RULE = "HOST-006";
    public static final int ADDRESS_SCORE = 85;
    public static final int LISTED_DOMAIN_SCORE = 85;
    public static final int LOOKALIKE_SCORE = 60;

    private final Predicate<String> badAddress;
    private final Predicate<String> badDomain;
    private final Function<String, Optional<String>> imitates;

    /**
     * @param badAddress true for an IP on a threat list (feeds or your own indicators)
     * @param badDomain  true for a domain on a threat list
     * @param imitates   the brand a domain imitates, if any (the web module's look-alike checker)
     */
    public HostNetworkDetector(Predicate<String> badAddress, Predicate<String> badDomain,
                               Function<String, Optional<String>> imitates) {
        this.badAddress = badAddress;
        this.badDomain = badDomain;
        this.imitates = imitates;
    }

    @Override
    public Set<String> ruleIds() {
        return Set.of(ADDRESS_RULE, DOMAIN_RULE);
    }

    @Override
    public List<Finding> detect(SysmonEvent e) {
        if (e.eventId() == SysmonEvent.NETWORK_CONNECT) {
            return connection(e);
        }
        if (e.eventId() == SysmonEvent.DNS_QUERY) {
            return lookup(e);
        }
        return List.of();
    }

    private List<Finding> connection(SysmonEvent e) {
        String ip = e.get("DestinationIp");
        if (ip.isEmpty() || !badAddress.test(ip)) {
            return List.of();
        }
        String program = SysmonEvent.fileName(e.get("Image"));
        return List.of(finding(ADDRESS_RULE, e, ip, ADDRESS_SCORE, program + " connected to an address on a threat list",
                "program", e.get("Image"), "port", e.get("DestinationPort"), "outgoing", e.get("Initiated")));
    }

    private List<Finding> lookup(SysmonEvent e) {
        String name = e.get("QueryName").toLowerCase(Locale.ROOT);
        String domain = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;   // "example.com." -> "example.com"
        if (domain.isEmpty()) {
            return List.of();
        }
        String program = SysmonEvent.fileName(e.get("Image"));
        if (badDomain.test(domain)) {
            return List.of(finding(DOMAIN_RULE, e, domain, LISTED_DOMAIN_SCORE,
                    program + " looked up a domain on a threat list", "program", e.get("Image")));
        }
        Optional<String> brand = imitates.apply(domain);
        return brand.map(b -> List.of(finding(DOMAIN_RULE, e, domain, LOOKALIKE_SCORE,
                program + " looked up a look-alike of " + b, "program", e.get("Image"), "imitates", b))).orElse(List.of());
    }
}
