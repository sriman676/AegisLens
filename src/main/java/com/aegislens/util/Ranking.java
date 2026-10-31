package com.aegislens.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * The first n items in their natural order, for example the worst findings (Finding sorts the highest severity first).
 */
public final class Ranking {

    private Ranking() {
    }

    /** A sorted copy of the first n items (fewer if there are fewer); the input is not changed. */
    public static <T extends Comparable<? super T>> List<T> topN(Collection<? extends T> items, int n) {
        List<T> sorted = new ArrayList<>(items);
        Collections.sort(sorted);
        return List.copyOf(sorted.subList(0, Math.min(Math.max(n, 0), sorted.size())));
    }
}
