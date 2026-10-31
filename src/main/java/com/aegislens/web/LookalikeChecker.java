package com.aegislens.web;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Spots domains that imitate a well-known one (rules/top-domains.txt): "paypa1-secure-login.example.test" imitates
 * paypal.com. Each part of the host (split at dots and dashes) is normalised first: punycode is decoded, look-alike
 * letters from other alphabets become Latin (Cyrillic "а" -> "a"), and 0->o, 1->l, 3->e, 5->s, rn->m. A part that then
 * equals a brand name, or is within edit distance 2 of a brand name of 6+ letters, is a lookalike, unless the host
 * really belongs to that brand. Short brands only match exactly, so "email" is not taken for "gmail".
 */
public final class LookalikeChecker {

    public static final int MAX_DISTANCE = 2;
    /** Brands shorter than this only match exactly (after normalising). */
    public static final int FUZZY_MIN_LENGTH = 6;
    private static final Map<Character, Character> CONFUSABLE = Map.ofEntries(
            Map.entry('а', 'a'), Map.entry('е', 'e'), Map.entry('о', 'o'), Map.entry('р', 'p'), Map.entry('с', 'c'),
            Map.entry('у', 'y'), Map.entry('х', 'x'), Map.entry('і', 'i'), Map.entry('ј', 'j'), Map.entry('ԁ', 'd'),
            Map.entry('ӏ', 'l'), Map.entry('ɡ', 'g'), Map.entry('ο', 'o'), Map.entry('α', 'a'), Map.entry('ν', 'v'),
            Map.entry('ı', 'i'), Map.entry('0', 'o'), Map.entry('1', 'l'), Map.entry('3', 'e'), Map.entry('5', 's'));

    private final Set<String> domains;

    public LookalikeChecker(Set<String> domains) {
        this.domains = new TreeSet<>(domains);
    }

    /** The bundled list of well-known domains. */
    public static LookalikeChecker bundled() throws IOException {
        Set<String> d = new TreeSet<>();
        try (InputStream in = LookalikeChecker.class.getResourceAsStream("/rules/top-domains.txt");
             BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                String t = line.strip().toLowerCase(Locale.ROOT);
                if (!t.isEmpty() && !t.startsWith("#")) {
                    d.add(t);
                }
            }
        }
        return new LookalikeChecker(d);
    }

    /** The well-known domain this host imitates, if any. */
    public Optional<String> imitates(String host) {
        String h = host == null ? "" : host.toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        for (String real : domains) {
            if (h.equals(real) || h.endsWith("." + real)) {
                return Optional.empty();                      // it IS the brand (or one of its subdomains)
            }
        }
        for (String part : normalise(h).split("[.\\-]")) {
            for (String real : domains) {
                String brand = real.substring(0, real.indexOf('.'));
                if (brand.length() >= 4 && (part.equals(brand)
                        || brand.length() >= FUZZY_MIN_LENGTH && distance(part, brand) <= MAX_DISTANCE)) {
                    return Optional.of(real);
                }
            }
        }
        return Optional.empty();
    }

    /** Punycode decoded, accents removed, confusable characters mapped to Latin, "rn" read as "m". */
    static String normalise(String host) {
        String unicode;
        try {
            unicode = IDN.toUnicode(host);
        } catch (IllegalArgumentException e) {
            unicode = host;
        }
        String plain = Normalizer.normalize(unicode, Normalizer.Form.NFKD).replaceAll("\\p{M}", "");
        StringBuilder sb = new StringBuilder(plain.length());
        for (char c : plain.toCharArray()) {
            sb.append(CONFUSABLE.getOrDefault(c, c));
        }
        return sb.toString().replace("rn", "m");
    }

    /** Levenshtein edit distance (insert, delete, replace = 1 each). */
    static int distance(String a, String b) {
        int[][] d = new int[a.length() + 1][b.length() + 1];
        for (int i = 0; i <= a.length(); i++) {
            d[i][0] = i;
        }
        for (int j = 0; j <= b.length(); j++) {
            d[0][j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            for (int j = 1; j <= b.length(); j++) {
                int replace = d[i - 1][j - 1] + (a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1);
                d[i][j] = Math.min(replace, Math.min(d[i - 1][j], d[i][j - 1]) + 1);
            }
        }
        return d[a.length()][b.length()];
    }
}
