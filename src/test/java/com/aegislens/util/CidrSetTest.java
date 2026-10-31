package com.aegislens.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CidrSetTest {

    @Test
    void rangesOfManyPrefixLengths() {
        CidrSet set = new CidrSet();
        assertTrue(set.add("10.0.0.0/8"));
        assertTrue(set.add("172.16.0.0/12"));
        assertTrue(set.add("203.0.113.45"));
        assertTrue(set.add("2001:db8::/32"));
        assertTrue(set.contains("10.255.0.1"));
        assertTrue(set.contains("172.31.1.1"));
        assertFalse(set.contains("172.32.0.1"));
        assertTrue(set.contains("203.0.113.45"));
        assertFalse(set.contains("203.0.113.46"));
        assertTrue(set.contains("2001:db8:1::5"));
        assertFalse(set.contains("2001:db9::5"));
        assertEquals(4, set.size());
    }

    @Test
    void familiesNeverMixAndJunkIsRefused() {
        CidrSet set = new CidrSet();
        set.add("0.0.0.0/0");
        assertTrue(set.contains("8.8.8.8"));
        assertFalse(set.contains("2001:db8::1"));
        assertFalse(set.add("example.com"));
        assertFalse(set.add("10.0.0.0/33"));
        assertFalse(set.add("999.1.1.1"));
        assertFalse(set.contains("example.com"), "never resolved");
        assertFalse(set.contains((String) null));
    }

    @Test
    void lookupsStayFastWithManyEntries() {
        CidrSet set = new CidrSet();
        for (int i = 0; i < 50_000; i++) {
            set.add("100." + (i >> 8 & 255) + "." + (i & 255) + ".0/24");
        }
        long start = System.nanoTime();
        for (int i = 0; i < 100_000; i++) {
            set.contains("100.1.2.3");
        }
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertTrue(set.contains("100.1.2.3"));
        assertTrue(ms < 2_000, "100 000 lookups took " + ms + " ms");
    }
}
