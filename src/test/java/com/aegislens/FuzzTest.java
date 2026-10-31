package com.aegislens;

import com.aegislens.ai.Redactor;
import com.aegislens.ai.Sanitizer;
import com.aegislens.app.AllowList;
import com.aegislens.app.OwnIntel;
import com.aegislens.core.AnalysisException;
import com.aegislens.core.Finding;
import com.aegislens.db.Database;
import com.aegislens.db.SqlConsole;
import com.aegislens.intel.FeedCatalog;
import com.aegislens.intel.FeedDefinition;
import com.aegislens.intel.FeedParsers;
import com.aegislens.intrusion.HostDetectionEngine;
import com.aegislens.intrusion.HostNetworkDetector;
import com.aegislens.intrusion.LogSource;
import com.aegislens.intrusion.SysmonEvent;
import com.aegislens.intrusion.SysmonXmlSource;
import com.aegislens.intrusion.SshLogSource;
import com.aegislens.intrusion.SyslogParser;
import com.aegislens.intrusion.Thresholds;
import com.aegislens.intrusion.WebLogSource;
import com.aegislens.malware.FileScanner;
import com.aegislens.ui.ConsoleCommands;
import com.aegislens.ui.SafeText;
import com.aegislens.util.CidrSet;
import com.aegislens.util.InjectionPatterns;
import com.aegislens.web.HtmlAnalyzer;
import com.aegislens.web.LookalikeChecker;
import com.aegislens.web.UrlAnalyzer;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * R13 fuzzing: random bytes, random text and mutated real lines go into every parser and analyzer that reads
 * untrusted input. Only the exceptions each one declares are allowed; anything else (NullPointerException,
 * StringIndexOutOfBounds, StackOverflowError ...) is a bug and fails with the input that caused it.
 * Normal build: about half a second per target. Long run: mvn test -Dtest=FuzzTest -Dfuzz.seconds=60
 */
class FuzzTest {

    @FunctionalInterface
    interface Target {
        void accept(String input) throws Exception;
    }

    private final Random random = new Random(Long.getLong("fuzz.seed", 307L));
    private final List<String> seeds = new ArrayList<>();

    @Test
    void untrustedInputNeverCrashesAParserOrAnalyzer() throws Exception {
        seeds.addAll(Files.readAllLines(Path.of("sample-data", "auth.log")));
        seeds.addAll(Files.readAllLines(Path.of("sample-data", "access.log")));
        seeds.addAll(Files.readAllLines(Path.of("sample-data", "urls.txt")));
        seeds.addAll(Files.readAllLines(Path.of("sample-data", "sysmon-sample.xml")));
        Map<String, Target> targets = targets();
        long perTarget = (long) (Double.parseDouble(System.getProperty("fuzz.seconds", "8")) * 1000 / targets.size());
        Map<String, Integer> runs = new LinkedHashMap<>();
        for (Map.Entry<String, Target> t : targets.entrySet()) {
            long end = System.currentTimeMillis() + Math.max(200, perTarget);
            int n = 0;
            while (System.currentTimeMillis() < end) {
                String input = nextInput();
                try {
                    t.getValue().accept(input);
                } catch (AnalysisException | SQLException | OwnIntelRefused expected) {
                    // declared: the input was rejected cleanly
                } catch (Throwable bug) {
                    fail(t.getKey() + " crashed with " + bug + " on input: " + printable(input), bug);
                }
                n++;
            }
            runs.put(t.getKey(), n);
        }
        System.out.println("[fuzz] inputs per target: " + runs);
        assertTrue(runs.values().stream().allMatch(n -> n > 50), runs.toString());
    }

    /** OwnIntel's RefusedException, wrapped so it can sit in the multi-catch above. */
    static final class OwnIntelRefused extends Exception {
        OwnIntelRefused(Exception cause) {
            super(cause);
        }
    }

    private Map<String, Target> targets() throws Exception {
        Map<String, Target> t = new LinkedHashMap<>();
        LogSource ssh = new SshLogSource();
        LogSource web = new WebLogSource(true);
        LogSource syslog = new SyslogParser(new SshLogSource(), new WebLogSource(), Clock.systemUTC(), ZoneOffset.UTC);
        FileScanner scanner = new FileScanner(h -> false, 1);
        UrlAnalyzer urls = new UrlAnalyzer(LookalikeChecker.bundled(), new InjectionPatterns(Thresholds.DEFAULT_INJECTION), v -> false);
        HtmlAnalyzer html = new HtmlAnalyzer();
        InjectionPatterns injection = new InjectionPatterns(Thresholds.DEFAULT_INJECTION);
        Redactor redactor = new Redactor();
        Database db = Database.inMemory();
        SqlConsole sql = new SqlConsole(db);
        Properties p = new Properties();
        p.load(FeedCatalog.class.getResourceAsStream("/intel/feeds.properties"));
        List<FeedDefinition> feeds = FeedCatalog.parse(p);
        t.put("ssh log line", ssh::parse);
        t.put("web log line", web::parse);
        t.put("syslog line", syslog::parse);
        t.put("file bytes (any type)", s -> scanner.scan(bytes(s), "fuzz.bin"));
        t.put("PE-looking bytes", s -> scanner.scan(withPrefix("MZ", s), "fuzz.exe"));
        t.put("ELF-looking bytes", s -> scanner.scan(withPrefix("\u007fELF", s), "fuzz.elf"));
        t.put("url", urls::analyze);
        t.put("html", s -> html.analyze(s, URI.create("http://fuzz.example.test/")));
        t.put("injection patterns", injection::find);
        t.put("lookalike", s -> LookalikeChecker.bundled().imitates(s));
        t.put("ip literal / cidr", s -> {
            CidrSet.literal(s);
            new CidrSet().add(s);
        });
        t.put("allow-list", s -> {
            AllowList.parse(s);
            AllowList.invalidEntries(s);
        });
        t.put("own indicator", s -> {
            try {
                OwnIntel.normalise(List.of("IP", "CIDR", "HASH", "DOMAIN", "URL").get(Math.abs(s.hashCode() % 5)), s);
            } catch (Exception refused) {
                throw new OwnIntelRefused(refused);
            }
        });
        HostDetectionEngine host = new HostDetectionEngine(new HostNetworkDetector(ip -> false, d -> false,
                LookalikeChecker.bundled()::imitates), rule -> true);
        Path xml = Files.createTempFile("fuzz-sysmon", ".xml");
        xml.toFile().deleteOnExit();
        t.put("sysmon export (XML)", s -> {
            Files.write(xml, bytes(s));                     // bytes(): any input, even a lone surrogate
            new SysmonXmlSource().parse(xml);
        });
        t.put("sysmon fields (detectors)", s -> {
            for (int id : new int[] {1, 3, 11, 13, 22}) {
                host.process(new SysmonEvent(Instant.EPOCH, id, s, Map.of("Image", s, "CommandLine", s, "ParentImage", s,
                        "DestinationIp", s, "QueryName", s, "TargetFilename", s, "TargetObject", s, "Details", s), s));
            }
        });
        t.put("feed body", s -> {
            for (FeedDefinition f : feeds) {
                FeedParsers.parse(f, s);
            }
        });
        t.put("sql console", sql::run);
        t.put("console command", s -> ConsoleCommands.parse(s));
        t.put("display text", s -> {
            SafeText.shorten(s);
            SafeText.target(s);
            SafeText.time(s);
        });
        t.put("ai redaction", s -> redactor.redact(new Finding("fuzz", s.isBlank() ? "x" : s, "NET-001", 50, s.isBlank() ? "x" : s)));
        t.put("ai sanitizer", s -> Sanitizer.clean(s, 500));
        return t;
    }

    /** A random mix: real lines mutated, random printable text, random bytes as text, and nasty special cases. */
    private String nextInput() {
        return switch (random.nextInt(6)) {
            case 0 -> mutate(seeds.get(random.nextInt(seeds.size())));
            case 1 -> randomText(random.nextInt(300), 32, 127);
            case 2 -> randomText(random.nextInt(300), 0, 0x3000);
            case 3 -> SPECIAL.get(random.nextInt(SPECIAL.size()));
            case 4 -> seeds.get(random.nextInt(seeds.size())).repeat(1 + random.nextInt(50));
            default -> new String(randomBytes(random.nextInt(2000)), StandardCharsets.ISO_8859_1);
        };
    }

    private static final List<String> SPECIAL = List.of("", " ", "\u0000", "%", "%%%%", "%2", "%ZZ", "%u0000", "‮",
            "[", "]", "[::1", "::", ":::::", "1.2.3", "999.999.999.999", "0.0.0.0/33", "a/-1", "x".repeat(70_000),
            "<<<<<<", "<form action=", "<iframe", "'\"><script>", "http://", "https://@", "http://[", "xn--", "xn--.xn--",
            "\uD800", "\uDFFF", "\r\n\r\n", "${jndi:ldap://x}", "1=1--", "SELECT", "WITH", "EXPLAIN", "--", "/*");

    private String mutate(String line) {
        StringBuilder sb = new StringBuilder(line);
        for (int i = 0, n = 1 + random.nextInt(5); i < n && !sb.isEmpty(); i++) {
            int at = random.nextInt(sb.length());
            switch (random.nextInt(3)) {
                case 0 -> sb.deleteCharAt(at);
                case 1 -> sb.insert(at, (char) random.nextInt(0x2100));
                default -> sb.setCharAt(at, "%[]<>\"'\\ :@/.0".charAt(random.nextInt(14)));
            }
        }
        return sb.toString();
    }

    private String randomText(int length, int from, int to) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) (from + random.nextInt(to - from)));
        }
        return sb.toString();
    }

    private byte[] randomBytes(int length) {
        byte[] b = new byte[length];
        random.nextBytes(b);
        return b;
    }

    private static byte[] bytes(String s) {
        byte[] b = s.getBytes(StandardCharsets.ISO_8859_1);
        return b.length == 0 ? new byte[] {0} : b;
    }

    private static byte[] withPrefix(String magic, String s) {
        return bytes(magic + s);
    }

    private static String printable(String s) {
        String t = s.length() > 300 ? s.substring(0, 300) + "...(" + s.length() + " chars)" : s;
        StringBuilder sb = new StringBuilder();
        for (char c : t.toCharArray()) {
            sb.append(c < 32 || c > 126 ? String.format("\\u%04x", (int) c) : String.valueOf(c));
        }
        return sb.toString();
    }
}
