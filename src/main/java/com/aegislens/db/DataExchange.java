package com.aegislens.db;

import com.aegislens.core.Finding;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Export and import of findings (D11). Export writes the rows of a search filter to CSV (RFC 4180) or JSON with byte
 * streams; CSV cells that a spreadsheet would run as a formula are made harmless. Import reads a CSV written by export
 * and saves it in ONE transaction: one bad row and nothing is imported.
 */
public final class DataExchange {

    /** Most findings one export writes. */
    public static final int MAX_EXPORT = 100_000;
    /** Most rows one import accepts. */
    public static final int MAX_IMPORT_ROWS = 100_000;
    /** Largest CSV file import reads. */
    public static final long MAX_IMPORT_BYTES = 50L * 1024 * 1024;
    /** The CSV header, also the column order. */
    public static final List<String> COLUMNS = List.of("id", "created_at", "severity", "score", "rule_id", "rule_name",
            "module", "target", "description", "status");

    private static final Set<String> STATUSES = Set.of("OPEN", "RESOLVED", "FALSE_POSITIVE");
    private static final Set<String> MODULES = Set.of("MALWARE", "INTRUSION", "WEB", "SANDBOX", "HOST");
    /** A cell starting with one of these is a formula in Excel/LibreOffice (CSV injection). */
    private static final String FORMULA_START = "=+-@\t\r";

    /** File formats for export. */
    public enum Format { CSV, JSON }

    /** A CSV row that cannot be imported; nothing was saved. Line numbers start at 1 (the header). */
    public static final class ImportException extends Exception {
        private final int line;

        public ImportException(int line, String message) {
            super("line " + line + ": " + message);
            this.line = line;
        }

        public int line() {
            return line;
        }
    }

    private final Database db;
    private final FindingSearch search;

    public DataExchange(Database db) {
        this.db = db;
        this.search = new FindingSearch(db);
    }

    /** Writes every finding matching the filter (newest first, at most MAX_EXPORT) and returns how many were written. */
    public int export(FindingSearch.Filter filter, Path file, Format format) throws SQLException, IOException {
        List<ReportRepository.DetailRow> rows = collect(filter);
        try (OutputStream out = new FileOutputStream(file.toFile())) {
            if (format == Format.CSV) {
                writeCsv(rows, out);
            } else {
                writeJson(rows, out);
            }
        }
        return rows.size();
    }

    /** Reads a CSV written by export and saves its findings; returns how many. All or nothing. */
    public int importCsv(Path file) throws IOException, SQLException, ImportException {
        if (Files.size(file) > MAX_IMPORT_BYTES) {
            throw new ImportException(1, "file is larger than " + MAX_IMPORT_BYTES / (1024 * 1024) + " MB");
        }
        String text;
        try (InputStream in = new FileInputStream(file.toFile())) {
            text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        List<Imported> rows = parse(text);
        String label = "import: " + file.getFileName();
        db.transaction(c -> {
            Map<String, Long> sessions = new LinkedHashMap<>();
            ScanSessionRepository sessionRepo = new ScanSessionRepository(db);
            List<Finding> findings = new ArrayList<>();
            for (Imported row : rows) {
                Long session = sessions.get(row.module());
                if (session == null) {
                    session = sessionRepo.begin(row.module(), label);
                    sessions.put(row.module(), session);
                }
                row.finding().setSessionId(session);
                findings.add(row.finding());
            }
            new FindingRepository(db).saveAll(findings);
            for (long id : sessions.values()) {
                sessionRepo.finish(id, true);
            }
            return null;
        });
        return rows.size();
    }

    private List<ReportRepository.DetailRow> collect(FindingSearch.Filter filter) throws SQLException {
        List<ReportRepository.DetailRow> all = new ArrayList<>();
        Long before = null;
        while (all.size() < MAX_EXPORT) {
            List<ReportRepository.DetailRow> page = search.search(filter, before, FindingSearch.MAX_PAGE);
            all.addAll(page.subList(0, Math.min(page.size(), MAX_EXPORT - all.size())));
            if (page.size() < FindingSearch.MAX_PAGE) {
                break;
            }
            before = page.get(page.size() - 1).id();
        }
        return all;
    }

    // ---- CSV writing ----

    static void writeCsv(List<ReportRepository.DetailRow> rows, OutputStream out) throws IOException {
        Writer w = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
        writeLine(w, COLUMNS);
        for (ReportRepository.DetailRow r : rows) {
            writeLine(w, List.of(String.valueOf(r.id()), r.createdAt(), r.severity(), String.valueOf(r.score()),
                    r.ruleId(), nullToEmpty(r.ruleName()), r.module(), r.target(), r.description(), r.status()));
        }
        w.flush();
    }

    private static void writeLine(Writer w, List<String> cells) throws IOException {
        for (int i = 0; i < cells.size(); i++) {
            if (i > 0) {
                w.write(',');
            }
            w.write(csvCell(cells.get(i)));
        }
        w.write("\r\n");                     // RFC 4180 line ending
    }

    /** Defuses formulas (a leading ' makes spreadsheets show the text) and quotes the cell when needed. */
    static String csvCell(String value) {
        String v = value;
        if (!v.isEmpty() && FORMULA_START.indexOf(v.charAt(0)) >= 0) {
            v = "'" + v;
        }
        if (v.contains(",") || v.contains("\"") || v.contains("\n") || v.contains("\r")) {
            v = "\"" + v.replace("\"", "\"\"") + "\"";
        }
        return v;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    // ---- JSON writing ----

    private static void writeJson(List<ReportRepository.DetailRow> rows, OutputStream out) throws IOException {
        List<Map<String, Object>> list = new ArrayList<>();
        for (ReportRepository.DetailRow r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", r.id());
            m.put("created_at", r.createdAt());
            m.put("severity", r.severity());
            m.put("score", r.score());
            m.put("rule_id", r.ruleId());
            m.put("rule_name", r.ruleName());
            m.put("module", r.module());
            m.put("target", r.target());
            m.put("description", r.description());
            m.put("status", r.status());
            m.put("ioc_hit", r.iocHit());
            list.add(m);
        }
        new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValue(out, Map.of("findings", list));
    }

    // ---- CSV reading ----

    /** One parsed import row: its module (for the session) and the finding. */
    private record Imported(String module, Finding finding) {
    }

    static List<Imported> parse(String text) throws ImportException {
        List<List<String>> records = CsvReader.read(text);
        if (records.isEmpty() || !records.get(0).equals(COLUMNS)) {
            throw new ImportException(1, "header must be " + String.join(",", COLUMNS));
        }
        if (records.size() - 1 > MAX_IMPORT_ROWS) {
            throw new ImportException(1, "more than " + MAX_IMPORT_ROWS + " rows");
        }
        List<Imported> rows = new ArrayList<>();
        for (int i = 1; i < records.size(); i++) {
            rows.add(toFinding(i + 1, records.get(i)));
        }
        return rows;
    }

    private static Imported toFinding(int line, List<String> cells) throws ImportException {
        if (cells.size() != COLUMNS.size()) {
            throw new ImportException(line, "expected " + COLUMNS.size() + " cells but found " + cells.size());
        }
        Map<String, String> row = new LinkedHashMap<>();
        for (int i = 0; i < cells.size(); i++) {
            row.put(COLUMNS.get(i), undoFormulaGuard(cells.get(i)));
        }
        String module = oneOf(line, row.get("module"), MODULES, "module");
        String status = oneOf(line, row.get("status"), STATUSES, "status");
        try {
            Finding f = new Finding("import", row.get("target"), row.get("rule_id"), Integer.parseInt(row.get("score")),
                    row.get("description"), null, Instant.parse(row.get("created_at")));
            f.setStatus(status);
            return new Imported(module, f);
        } catch (NumberFormatException e) {
            throw new ImportException(line, "score is not a number");
        } catch (DateTimeParseException e) {
            throw new ImportException(line, "created_at is not an ISO-8601 time");
        } catch (IllegalArgumentException e) {           // Finding refuses blank fields and scores outside 0-100
            throw new ImportException(line, e.getMessage());
        }
    }

    private static String oneOf(int line, String value, Set<String> allowed, String column) throws ImportException {
        if (!allowed.contains(value)) {
            throw new ImportException(line, column + " must be one of " + allowed + " but was '" + value + "'");
        }
        return value;
    }

    /** Export put a ' in front of formula-looking cells; take it off again. */
    static String undoFormulaGuard(String cell) {
        if (cell.length() > 1 && cell.charAt(0) == '\'' && FORMULA_START.indexOf(cell.charAt(1)) >= 0) {
            return cell.substring(1);
        }
        return cell;
    }

    /** A small RFC 4180 reader: quoted cells may hold commas, "" for a quote, and line breaks. */
    static final class CsvReader {

        private CsvReader() {
        }

        static List<List<String>> read(String text) throws ImportException {
            List<List<String>> records = new ArrayList<>();
            List<String> record = new ArrayList<>();
            StringBuilder cell = new StringBuilder();
            boolean quoted = false;
            int line = 1;
            for (int i = 0; i < text.length(); i++) {
                char ch = text.charAt(i);
                if (quoted) {
                    if (ch == '"' && i + 1 < text.length() && text.charAt(i + 1) == '"') {
                        cell.append('"');
                        i++;
                    } else if (ch == '"') {
                        quoted = false;
                    } else {
                        cell.append(ch);
                    }
                } else if (ch == '"' && cell.isEmpty()) {
                    quoted = true;
                } else if (ch == ',') {
                    record.add(cell.toString());
                    cell.setLength(0);
                } else if (ch == '\n' || ch == '\r') {
                    if (ch == '\r' && i + 1 < text.length() && text.charAt(i + 1) == '\n') {
                        i++;
                    }
                    record.add(cell.toString());
                    cell.setLength(0);
                    records.add(record);
                    record = new ArrayList<>();
                    line++;
                } else {
                    cell.append(ch);
                }
            }
            if (quoted) {
                throw new ImportException(line, "a quoted cell is never closed");
            }
            if (!cell.isEmpty() || !record.isEmpty()) {
                record.add(cell.toString());
                records.add(record);
            }
            records.removeIf(r -> r.size() == 1 && r.get(0).isEmpty());   // blank lines
            return records;
        }
    }
}
