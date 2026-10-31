package com.aegislens.intrusion;

import com.aegislens.util.LruMap;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;

/**
 * Counts distinct values per key (for example distinct user names per IP) inside a sliding time window, and
 * remembers when each key last fired so a burst alerts only once. Shared by PasswordSprayDetector and PathScanDetector.
 */
final class WindowedDistinctCounter<T> {

    private record Seen<T>(Instant at, T value) {
    }

    private static final class KeyState<T> {
        final LinkedList<Seen<T>> seen = new LinkedList<>();
        Instant firedAt;
    }

    private final Duration window;
    private final Map<String, KeyState<T>> byKey;

    WindowedDistinctCounter(Duration window, int maxKeys) {
        this.window = window;
        this.byKey = new LruMap<>(maxKeys);
    }

    /** Records value for key at time and returns how many distinct values the key has inside the window. */
    int add(String key, T value, Instant at) {
        KeyState<T> s = byKey.computeIfAbsent(key, k -> new KeyState<>());
        Instant cutoff = at.minus(window);
        Iterator<Seen<T>> it = s.seen.iterator();
        while (it.hasNext() && it.next().at().isBefore(cutoff)) {
            it.remove();
        }
        s.seen.addLast(new Seen<>(at, value));
        Set<T> distinct = new HashSet<>();
        for (Seen<T> x : s.seen) {
            distinct.add(x.value());
        }
        return distinct.size();
    }

    /** True (and remembers it) if the key has not fired inside the current window. */
    boolean fireOnce(String key, Instant at) {
        KeyState<T> s = byKey.get(key);
        if (s.firedAt != null && !s.firedAt.isBefore(at.minus(window))) {
            return false;
        }
        s.firedAt = at;
        return true;
    }

    int trackedKeys() {
        return byKey.size();
    }
}
