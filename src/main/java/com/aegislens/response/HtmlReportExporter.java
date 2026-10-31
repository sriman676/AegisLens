package com.aegislens.response;

import com.aegislens.app.Branding;
import com.aegislens.core.Severity;
import com.aegislens.db.Database;
import com.aegislens.db.FindingRepository;
import com.aegislens.db.ReportRepository;
import com.aegislens.db.ReportRepository.DayCount;
import com.aegislens.db.ReportRepository.DetailRow;
import com.aegislens.db.ReportRepository.RuleCount;
import com.aegislens.db.ReportRepository.TargetStats;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Writes a one-page, self-contained HTML report: severity counts, top attackers, rules, findings per day and
 * the newest findings. Every value is HTML-escaped and the page has no script and a Content-Security-Policy that
 * forbids loading anything, so hostile text from a log (for example "&lt;script&gt;") stays plain text.
 */
public final class HtmlReportExporter {

    /** Newest findings listed in the report. */
    public static final int FINDINGS = 200;
    public static final int TOP = 10;
    public static final int DAYS = 14;

    private final FindingRepository findings;
    private final ReportRepository reports;

    public HtmlReportExporter(Database db) {
        this.findings = new FindingRepository(db);
        this.reports = new ReportRepository(db);
    }

    /** Writes the report without branding and returns how many findings it lists. */
    public int export(Path file, Instant now) throws IOException, SQLException {
        return export(file, now, new Branding("", null));
    }

    /** Writes the report with your organisation's name and logo (Settings > Appearance) at the top. */
    public int export(Path file, Instant now, Branding brand) throws IOException, SQLException {
        List<DetailRow> rows = reports.findingsWithContext(FINDINGS);
        StringBuilder html = new StringBuilder(64 * 1024);
        html.append("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n")
                .append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">\n")
                .append("<title>").append(esc(title(brand))).append("</title>\n<style>").append(CSS).append("</style></head><body>\n")
                .append(logo(brand)).append("<h1>").append(esc(title(brand))).append("</h1><p class=\"sub\">Generated ")
                .append(esc(now.toString()))
                .append(". False positives are left out.</p>\n");
        severityCards(html, findings.countBySeverity());
        targets(html, "Top attackers (intrusion)", reports.topAttackers(TOP));
        rules(html, reports.perRule(1));
        days(html, reports.perDay(DAYS, now));
        findingTable(html, rows);
        html.append("</body></html>\n");
        try (Writer w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file.toFile()), StandardCharsets.UTF_8))) {
            w.write(html.toString());
        }
        return rows.size();
    }

    private static String title(Branding brand) {
        return brand.name().isBlank() ? "AegisLens report" : brand.name() + " · AegisLens report";
    }

    /** The logo as a data: URI (the bytes were checked to be PNG or JPEG when it was stored). */
    private static String logo(Branding brand) {
        if (brand.logo() == null) {
            return "";
        }
        String type = Branding.imageType(brand.logo()).orElse("image/png");
        return "<img class=\"logo\" alt=\"logo\" src=\"data:" + type + ";base64,"
                + Base64.getEncoder().encodeToString(brand.logo()) + "\">";
    }

    private static void severityCards(StringBuilder h, Map<Severity, Integer> counts) {
        h.append("<div class=\"cards\">");
        for (Severity s : List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)) {
            h.append("<div class=\"card ").append(s.name().toLowerCase(Locale.ROOT)).append("\"><b>")
                    .append(counts.getOrDefault(s, 0)).append("</b><span>").append(s).append("</span></div>");
        }
        h.append("</div>\n");
    }

    private static void targets(StringBuilder h, String title, List<TargetStats> list) {
        h.append("<h2>").append(esc(title)).append("</h2><table><tr><th>Target</th><th>Findings</th><th>Top score</th>")
                .append("<th>First seen</th><th>Last seen</th></tr>\n");
        for (TargetStats t : list) {
            row(h, t.target(), String.valueOf(t.count()), String.valueOf(t.maxScore()), t.firstSeen(), t.lastSeen());
        }
        h.append("</table>\n");
    }

    private static void rules(StringBuilder h, List<RuleCount> list) {
        h.append("<h2>Rules</h2><table><tr><th>Rule</th><th>Name</th><th>Findings</th><th>Top score</th></tr>\n");
        for (RuleCount r : list) {
            row(h, r.ruleId(), r.ruleName(), String.valueOf(r.count()), String.valueOf(r.maxScore()));
        }
        h.append("</table>\n");
    }

    private static void days(StringBuilder h, List<DayCount> list) {
        Map<String, int[]> perDay = new TreeMap<>();
        for (DayCount d : list) {
            perDay.computeIfAbsent(d.day(), k -> new int[4])[Severity.valueOf(d.severity()).ordinal()] += d.count();
        }
        h.append("<h2>Findings per day (last ").append(DAYS).append(" days)</h2><table><tr><th>Day</th>")
                .append("<th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>\n");
        perDay.forEach((day, c) -> row(h, day, String.valueOf(c[Severity.CRITICAL.ordinal()]),
                String.valueOf(c[Severity.HIGH.ordinal()]), String.valueOf(c[Severity.MEDIUM.ordinal()]),
                String.valueOf(c[Severity.LOW.ordinal()])));
        h.append("</table>\n");
    }

    private static void findingTable(StringBuilder h, List<DetailRow> rows) {
        h.append("<h2>Newest findings</h2><table><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Module</th>")
                .append("<th>Target</th><th>What happened</th><th>Status</th></tr>\n");
        for (DetailRow r : rows) {
            row(h, r.createdAt(), r.severity() + " " + r.score(), r.ruleId(), r.module(), r.target(), r.description(), r.status());
        }
        h.append("</table>\n");
    }

    private static void row(StringBuilder h, String... cells) {
        h.append("<tr>");
        for (String c : cells) {
            h.append("<td>").append(esc(c)).append("</td>");
        }
        h.append("</tr>\n");
    }

    /** HTML-escapes text for element content and attribute values. Null becomes "". */
    static String esc(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(text.length());
        for (char ch : text.toCharArray()) {
            switch (ch) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(Character.isISOControl(ch) ? ' ' : ch);
            }
        }
        return sb.toString();
    }

    private static final String CSS = "body{font-family:Segoe UI,Helvetica,Arial,sans-serif;margin:32px;color:#0f172a}"
            + ".logo{height:56px;float:right}h1{margin:0}.sub{color:#64748b}table{border-collapse:collapse;width:100%;margin-bottom:24px;font-size:13px}"
            + "th,td{border-bottom:1px solid #e2e8f0;padding:6px 8px;text-align:left;vertical-align:top}th{color:#475569}"
            + ".cards{display:flex;gap:12px;margin:16px 0}.card{border-radius:12px;padding:12px 18px;min-width:110px;"
            + "border-top:4px solid}.card b{font-size:28px;display:block}.critical{border-color:#e11d48}"
            + ".high{border-color:#ea580c}.medium{border-color:#ca8a04}.low{border-color:#0891b2}";
}
