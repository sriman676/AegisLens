package com.aegislens.util;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A map that keeps at most maxSize entries and forgets the least recently used one when full, so per-IP state in
 * detectors can never grow without limit (bounded at 50 000 IPs). Not thread-safe: each detector is used
 * by one thread at a time. Extends LinkedHashMap&lt;K, V&gt; and overrides its protected removeEldestEntry.
 */
public class LruMap<K, V> extends LinkedHashMap<K, V> {

    private final int maxSize;

    public LruMap(int maxSize) {
        super(16, 0.75f, true);                  // access order: get() moves an entry to the "recent" end
        if (maxSize < 1) {
            throw new IllegalArgumentException("maxSize must be at least 1");
        }
        this.maxSize = maxSize;
    }

    @Override
    protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
        return size() > maxSize;
    }

    public int maxSize() {
        return maxSize;
    }
}
