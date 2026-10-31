package com.aegislens.db;

import com.aegislens.core.Finding;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** R18 D11: CSV round trip, formula defusing, all-or-nothing import, JSON shape. */
class DataExchangeTest {

    private static final Instant AT = Instant.parse("2026-10-30T08:00:00Z");

    @TempDir
    Path dir;

    @Test
    void csvRoundTripIntoAFreshDatabaseKeepsEveryField() throws Exception {
        Path csv = dir.resolve("findings.csv");
        List<ReportRepository.DetailRow> original;
        try (Database db = Database.inMemory()) {
            seed(db);
            original = new FindingSearch(db).search(FindingSearch.Filter.ALL, null, 100);
            assertEquals(3, new DataExchange(db).export(FindingSearch.Filter.ALL, csv, DataExchange.Format.CSV));
        }
        try (Database fresh = Database.inMemory()) {
            assertEquals(3, new DataExchange(fresh).importCsv(csv));
            List<ReportRepository.DetailRow> back = new FindingSearch(fresh).search(FindingSearch.Filter.ALL, null, 100);
            assertEquals(strip(original), strip(back));
        }
    }

    @Test
    void formulaCellsAreDefusedInTheFile() throws Exception {
        Path csv = dir.resolve("f.csv");
        try (Database db = Database.inMemory()) {
            seed(db);
            new DataExchange(db).export(FindingSearch.Filter.ALL, csv, DataExchange.Format.CSV);
        }
        String text = Files.readString(csv);
        assertTrue(text.contains("'=HYPERLINK(\"\"http://x.example\"\")"), text);
        assertFalse(text.contains(",=HYPERLINK"), "no cell starts with =");
        assertTrue(text.contains("\"line one\nline two, with comma\""), "RFC 4180 quoting");
    }

    @Test
    void oneBadRowMeansNothingIsImported() throws Exception {
        Path csv = dir.resolve("bad.csv");
        String header = String.join(",", DataExchange.COLUMNS);
        Files.writeString(csv, header + "\r\n"
                + "1,2026-10-30T08:00:00Z,HIGH,72,NET-001,,INTRUSION,203.0.113.4,ok row,OPEN\r\n"
                + "2,2026-10-30T08:00:00Z,HIGH,172,NET-001,,INTRUSION,203.0.113.4,score too high,OPEN\r\n");
        try (Database db = Database.inMemory()) {
            DataExchange.ImportException e = assertThrows(DataExchange.ImportException.class,
                    () -> new DataExchange(db).importCsv(csv));
            assertEquals(3, e.line());
            assertEquals(0, new FindingRepository(db).count());
            assertEquals(0, new ScanSessionRepository(db).count(), "no session was left behind either");
        }
    }

    @Test
    void wrongHeaderAndBadValuesGiveTheLineNumber() {
        String header = String.join(",", DataExchange.COLUMNS);
        assertEquals(1, assertThrows(DataExchange.ImportException.class,
                () -> DataExchange.parse("a,b,c\r\n")).line());
        assertEquals(2, assertThrows(DataExchange.ImportException.class,
                () -> DataExchange.parse(header + "\r\n1,yesterday,HIGH,70,R,,WEB,t,d,OPEN\r\n")).line());
        assertEquals(2, assertThrows(DataExchange.ImportException.class,
                () -> DataExchange.parse(header + "\r\n1,2026-10-30T08:00:00Z,HIGH,70,R,,IMPORT,t,d,OPEN\r\n")).line());
        assertThrows(DataExchange.ImportException.class, () -> DataExchange.parse(header + "\r\n\"never closed"));
    }

    @Test
    void jsonHasOneObjectPerFinding() throws Exception {
        Path json = dir.resolve("f.json");
        try (Database db = Database.inMemory()) {
            seed(db);
            new DataExchange(db).export(new FindingSearch.Filter(null, null, null, "MALWARE", null, null), json,
                    DataExchange.Format.JSON);
        }
        JsonNode root = new ObjectMapper().readTree(json.toFile());
        assertEquals(1, root.get("findings").size());
        assertEquals("MAL-001", root.get("findings").get(0).get("rule_id").asText());
        assertFalse(root.get("findings").get(0).get("ioc_hit").asBoolean());
    }

    private static void seed(Database db) throws SQLException {
        ScanSessionRepository sessions = new ScanSessionRepository(db);
        FindingRepository repo = new FindingRepository(db);
        long ssh = sessions.begin("INTRUSION", "auth.log");
        long mal = sessions.begin("MALWARE", "downloads");
        save(repo, ssh, "203.0.113.45", "NET-001", 72, "=HYPERLINK(\"http://x.example\")", "OPEN");
        save(repo, ssh, "198.51.100.7", "WEB-002", 85, "line one\nline two, with comma", "RESOLVED");
        save(repo, mal, "-invoice.exe", "MAL-001", 55, "@packed", "FALSE_POSITIVE");
    }

    private static void save(FindingRepository repo, long session, String target, String rule, int score, String text,
                             String status) throws SQLException {
        Finding f = new Finding("test", target, rule, score, text, null, AT);
        f.setSessionId(session);
        f.setStatus(status);
        repo.save(f);
    }

    /** Ids differ in a fresh database; everything else must be equal. */
    private static List<String> strip(List<ReportRepository.DetailRow> rows) {
        return rows.stream().map(r -> String.join("|", r.createdAt(), r.severity(), String.valueOf(r.score()), r.ruleId(),
                r.module(), r.target(), r.description(), r.status())).sorted().toList();
    }
}
