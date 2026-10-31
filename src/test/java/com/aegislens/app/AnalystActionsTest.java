package com.aegislens.app;

import com.aegislens.core.Finding;
import com.aegislens.db.BlockedIpRepository;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.ScanSessionRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.sql.SQLException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** The analyst actions shared by the Findings view and the AWT console. */
class AnalystActionsTest {

    private Database db;
    private ScanCoordinator coordinator;
    private AnalystActions actions;

    @BeforeEach
    void setUp() throws SQLException {
        db = Database.inMemory();
        coordinator = new ScanCoordinator(db, AppConfig.defaults());
        coordinator.start();
        actions = new AnalystActions(coordinator);
    }

    @AfterEach
    void tearDown() throws Exception {
        coordinator.shutdown();
        db.close();
    }

    @Test
    void aPublicAddressIsRecordedNotTheFirewall() throws Exception {
        assertTrue(actions.recordBlock("203.0.113.45", "brute force").contains("not touched"));
        assertTrue(new BlockedIpRepository(db).isBlocked("203.0.113.45"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "10.1.2.3", "192.168.0.10", "172.16.5.5", "169.254.1.1", "0.0.0.0",
            "224.0.0.1", "::1", "fe80::1", "fd00::5", "not-an-ip", "evil.example; rm -rf /", ""})
    void ownNetworkAndNonAddressesAreRefused(String target) {
        assertThrows(AnalystActions.RefusedException.class, () -> actions.recordBlock(target, "x"));
    }

    @Test
    void trustedAddressesAreNotBlockedAndTrustIsApplied() throws Exception {
        actions.trust("198.51.100.0/24");
        actions.trust("198.51.100.0/24");
        assertEquals("198.51.100.0/24", coordinator.setting(AllowList.SETTING, ""), "no duplicate entry");
        assertThrows(AnalystActions.RefusedException.class, () -> actions.recordBlock("198.51.100.7", "x"));
        assertThrows(AnalystActions.RefusedException.class, () -> actions.trust("not an ip"));
    }

    @Test
    void falsePositiveExplainAndText() throws Exception {
        long session = new ScanSessionRepository(db).begin("INTRUSION", "auth.log");
        Finding f = new Finding("ssh", "203.0.113.45", "NET-001", 72, "7 failed logins", Map.of("user", "root"), null);
        f.setSessionId(session);
        FindingRepository repo = new FindingRepository(db);
        repo.save(f);

        assertNotNull(actions.explain(f.id()).get(10, TimeUnit.SECONDS).text(), "offline templates always answer");
        actions.falsePositive(f.id());
        assertEquals(1, repo.count("FALSE_POSITIVE"));
        assertThrows(AnalystActions.RefusedException.class, () -> actions.falsePositive(999_999));
        String text = AnalystActions.asText(f);
        assertTrue(text.contains("NET-001") && text.contains("Target: 203.0.113.45") && text.contains("user: root"));
    }
}
