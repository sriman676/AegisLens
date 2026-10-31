package com.aegislens.intrusion;

import com.aegislens.core.Finding;
import com.aegislens.util.LruMap;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Map;

/**
 * NET-004: an IP's requests per minute jump far above its own normal rate. Keeps the last 60 one-minute counts per IP
 * and computes z = (this minute - mean) / standard deviation once at least 10 minutes are known. The deviation is never
 * taken below 1 request, so a perfectly steady history does not make every small change look infinite, and a minute
 * with fewer than 10 requests is never an anomaly. Older (out-of-order) lines are ignored.
 * Score 45 at z >= 3, 65 at z >= 4, 80 at z >= 5; fires again in the same minute only if the band rises.
 */
public class ZScoreDetector extends LogDetector {

    public static final String RULE = "NET-004";
    static final int HISTORY_MINUTES = 60;
    static final int MIN_SAMPLES = 10;
    static final double MIN_STDDEV = 1.0;
    /** Fewer requests than this in a minute is never an anomaly (a rarely seen IP would otherwise have a tiny mean). */
    static final int MIN_REQUESTS_PER_MINUTE = 10;

    /** Per-IP: completed minute counts (oldest first) and the minute being counted now. */
    private static final class Rate {
        final ArrayDeque<Integer> history = new ArrayDeque<>();
        long minute = Long.MIN_VALUE;
        int count;
        int alertedBand;
    }

    private final Thresholds t;
    private final Map<String, Rate> byIp;

    public ZScoreDetector(Thresholds thresholds) {
        super(RULE);
        this.t = thresholds;
        this.byIp = new LruMap<>(thresholds.maxTrackedIps());
    }

    @Override
    public List<Finding> detect(LogEvent e) {
        if (e.ip() == null) {
            return none();
        }
        Rate r = byIp.computeIfAbsent(e.ip(), ip -> new Rate());
        long minute = minuteOf(e.timestamp());
        if (minute < r.minute) {
            return none();                            // an older, out-of-order line: it belongs to a finished minute
        }
        roll(r, minute);
        r.count++;
        if (r.history.size() < MIN_SAMPLES || r.count < MIN_REQUESTS_PER_MINUTE) {
            return none();
        }
        double z = zScore(r);
        int band = band(z);
        if (band == 0 || band <= r.alertedBand) {
            return none();
        }
        r.alertedBand = band;
        return List.of(finding(e, scoreFor(band), String.format("%s made %d requests this minute, z-score %.1f against its normal rate",
                e.ip(), r.count, z), Map.of("perMinute", String.valueOf(r.count), "zScore", String.format("%.2f", z),
                "mean", String.format("%.2f", mean(r)))));
    }

    /** Moves to minute m, pushing finished minutes (and zeros for silent minutes) into the history. */
    private static void roll(Rate r, long m) {
        if (r.minute == Long.MIN_VALUE) {
            r.minute = m;
            return;
        }
        if (m == r.minute) {
            return;
        }
        long gap = Math.min(m - r.minute, HISTORY_MINUTES);
        push(r, r.count);
        for (long i = 1; i < gap; i++) {
            push(r, 0);
        }
        r.minute = m;
        r.count = 0;
        r.alertedBand = 0;
    }

    private static void push(Rate r, int value) {
        r.history.addLast(value);
        if (r.history.size() > HISTORY_MINUTES) {
            r.history.removeFirst();
        }
    }

    private static double mean(Rate r) {
        double sum = 0;
        for (int v : r.history) {
            sum += v;
        }
        return sum / r.history.size();
    }

    private static double zScore(Rate r) {
        double mean = mean(r);
        double sq = 0;
        for (int v : r.history) {
            sq += (v - mean) * (v - mean);
        }
        double std = Math.max(MIN_STDDEV, Math.sqrt(sq / r.history.size()));
        return (r.count - mean) / std;
    }

    private int band(double z) {
        if (z >= t.zScore() + 2) {
            return 3;
        }
        if (z >= t.zScore() + 1) {
            return 2;
        }
        return z >= t.zScore() ? 1 : 0;
    }

    private static int scoreFor(int band) {
        return switch (band) {
            case 3 -> 80;
            case 2 -> 65;
            default -> 45;
        };
    }

    private static long minuteOf(Instant at) {
        return at.getEpochSecond() / Duration.ofMinutes(1).toSeconds();
    }
}
