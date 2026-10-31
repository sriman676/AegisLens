package com.aegislens.app;

import com.aegislens.ai.ExplanationService;
import com.aegislens.core.Finding;
import com.aegislens.db.BlockedIpRepository;
import com.aegislens.db.FindingRepository;
import com.aegislens.util.IpRules;

import java.net.InetAddress;
import java.sql.SQLException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Future;

/**
 * The analyst's actions on a finding, shared by the JavaFX Findings view and the AWT Analyst Console so both behave the
 * same and are tested once: record a block, trust an address (allow-list), mark a false positive, ask for an
 * explanation, and copy a finding as plain text. "Block" only RECORDS the address for the export in R10; AegisLens
 * never changes a firewall itself.
 */
public final class AnalystActions {

    /** An action that was refused, with a reason the user can read. */
    public static final class RefusedException extends Exception {
        public RefusedException(String message) {
            super(message);
        }
    }

    private final ScanCoordinator coordinator;
    private final FindingRepository findings;
    private final BlockedIpRepository blocked;

    public AnalystActions(ScanCoordinator coordinator) {
        this.coordinator = coordinator;
        this.findings = new FindingRepository(coordinator.database());
        this.blocked = new BlockedIpRepository(coordinator.database());
    }

    /** Records a public IP as blocked. Refuses non-IPs, private/local addresses and anything on the allow-list. */
    public String recordBlock(String target, String reason) throws RefusedException, SQLException {
        Optional<String> problem = IpRules.whyNotBlockable(target);
        if (problem.isPresent()) {
            throw new RefusedException(problem.get() + "; only public addresses can be blocked.");
        }
        InetAddress ip = IpRules.blockable(target);
        if (AllowList.parse(coordinator.setting(AllowList.SETTING, "")).isTrusted(new Finding("ui", target, "UI", 0, "check"))) {
            throw new RefusedException(target + " is on your allow-list, so it is not blocked.");
        }
        blocked.block(ip.getHostAddress(), reason);
        return "Recorded " + ip.getHostAddress() + " as blocked (export it with the blocklist; the firewall is not touched).";
    }

    /** Adds an IP or range to the allow-list and applies it at once. */
    public String trust(String target) throws RefusedException, SQLException {
        if (!AllowList.invalidEntries(target).isEmpty()) {
            throw new RefusedException(target + " is not an IP address or range, so it cannot be trusted.");
        }
        Set<String> entries = new LinkedHashSet<>();              // keeps the order, ignores a repeat
        for (String e : coordinator.setting(AllowList.SETTING, "").split(",")) {
            if (!e.isBlank()) {
                entries.add(e.strip());
            }
        }
        entries.add(target.strip());
        coordinator.saveSetting(AllowList.SETTING, String.join(", ", entries));
        coordinator.reloadAllowList();
        return target.strip() + " is now trusted: new findings for it are dropped.";
    }

    /** Marks one finding as a false positive. */
    public String falsePositive(long findingId) throws RefusedException, SQLException {
        if (findings.updateStatusMany(List.of(findingId), "FALSE_POSITIVE") == 0) {
            throw new RefusedException("Finding " + findingId + " no longer exists.");
        }
        return "Finding " + findingId + " marked as a false positive.";
    }

    /** Starts an explanation with the automatic provider choice (cloud, local, then offline). */
    public Future<ExplanationService.Explanation> explain(long findingId) throws RefusedException, SQLException {
        Finding f = findings.findById(findingId).orElseThrow(() -> new RefusedException("Finding " + findingId + " no longer exists."));
        return coordinator.explain(f, ExplanationService.AUTO);
    }

    /** The finding as plain text for the clipboard or a ticket (never HTML). */
    public static String asText(Finding f) {
        StringBuilder sb = new StringBuilder();
        sb.append(f.severity()).append(' ').append(f.score()).append("  ").append(f.ruleId()).append('\n')
                .append("Target: ").append(f.target()).append('\n')
                .append("When: ").append(f.timestamp()).append('\n')
                .append("What: ").append(f.description()).append('\n');
        f.evidence().forEach((k, v) -> sb.append("  ").append(k).append(": ").append(v).append('\n'));
        return sb.toString();
    }
}
