package com.aegislens.response;

import com.aegislens.app.AllowList;
import com.aegislens.core.Finding;
import com.aegislens.db.BlockedIp;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.ScanSessionRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** R10: blocklist command files are safe and never contain log text; the HTML report escapes hostile text. */
class ResponseExportTest {

    private static final Instant NOW = Instant.parse("2026-10-30T12:00:00Z");

    @TempDir
    Path dir;

    @Test
    void blocklistFilesContainOnlyCanonicalPublicAddresses() throws Exception {
        List<BlockedIp> blocks = List.of(
                new BlockedIp("203.0.113.45", "7 failed logins; rm -rf / `reboot`", NOW),
                new BlockedIp("2001:db8::1", "x", NOW),
                new BlockedIp("10.0.0.5", "own network", NOW),
                new BlockedIp("198.51.100.7", "trusted partner", NOW),
                new BlockedIp("203.0.113.45 && shutdown", "injection attempt", NOW));
        BlocklistExporter.Result r = new BlocklistExporter(AllowList.parse("198.51.100.0/24")).export(blocks, dir, NOW);

        assertEquals(2, r.written());
        assertEquals(3, r.skipped().size());
        assertTrue(r.skipped().get("198.51.100.7").contains("allow-list"));
        assertEquals(BlocklistExporter.FILES.size(), r.files().size());
        for (Path f : r.files()) {
            String text = Files.readString(f);
            assertTrue(text.contains("NOT executed by AegisLens"), f.getFileName() + " has the warning header");
            for (String forbidden : List.of("rm -rf", "reboot", "shutdown", "10.0.0.5", "198.51.100.7", "failed logins")) {
                assertFalse(text.contains(forbidden), f.getFileName() + " must not contain " + forbidden);
            }
        }
        assertTrue(Files.readString(dir.resolve("blocklist.txt")).contains("203.0.113.45\n2001:db8:0:0:0:0:0:1\n"));
        assertTrue(Files.readString(dir.resolve("iptables.sh")).contains("ip6tables -I INPUT -s 2001:db8:0:0:0:0:0:1 -j DROP"));
        assertTrue(Files.readString(dir.resolve("nftables.nft")).contains("elements = { 203.0.113.45 }"));
        assertTrue(Files.readString(dir.resolve("windows-netsh.cmd")).contains("remoteip=203.0.113.45\r\n"));
    }

    @Test
    void emptyBlocklistStillGivesValidNftables() throws Exception {
        new BlocklistExporter(AllowList.parse("")).export(List.of(), dir, NOW);
        String nft = Files.readString(dir.resolve("nftables.nft"));
        assertFalse(nft.contains("elements = {  }"), "nft refuses an empty element list");
        assertFalse(nft.contains("@blocked4"));
    }

    @Test
    void htmlReportEscapesHostileTextAndHasNoScript() throws Exception {
        try (Database db = Database.inMemory()) {
            long session = new ScanSessionRepository(db).begin("INTRUSION", "access.log");
            Finding f = new Finding("web", "203.0.113.9\"><img src=x onerror=alert(1)>", "WEB-002", 85,
                    "GET /?q=<script>alert('x')</script>", null, NOW);
            f.setSessionId(session);
            new FindingRepository(db).save(f);
            Path html = dir.resolve("report.html");
            assertEquals(1, new HtmlReportExporter(db).export(html, NOW));
            String text = Files.readString(html);
            assertFalse(text.contains("<script>"), "no raw script tag");
            assertFalse(text.contains("<img"), "no raw img tag from the target");
            assertTrue(text.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
            assertTrue(text.contains("default-src 'none'"), "CSP blocks every load");
            assertTrue(text.contains("<b>1</b><span>CRITICAL</span>"));
        }
    }
}
