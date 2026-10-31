package com.aegislens.util;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Ranking.topN: generic, works on any Comparable collection, never changes its input. */
class RankingTest {

    @Test
    void firstNInNaturalOrder() {
        List<Integer> input = List.of(5, 1, 4, 2);
        assertEquals(List.of(1, 2), Ranking.topN(input, 2));
        assertEquals(List.of(5, 1, 4, 2), input, "input untouched");
        assertEquals(List.of("a", "b"), Ranking.topN(Set.of("b", "a"), 10), "n larger than the collection");
        assertEquals(List.of(), Ranking.topN(input, -1));
    }
}
