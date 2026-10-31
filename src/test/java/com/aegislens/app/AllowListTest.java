package com.aegislens.app;

import com.aegislens.core.Finding;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AllowListTest {

    @Test
    void ipv4AddressesAndRanges() {
        AllowList list = AllowList.parse("10.0.0.0/8, 192.168.1.7, 172.16.0.0/12");
        assertTrue(list.isTrusted(at("10.20.30.40")));
        assertTrue(list.isTrusted(at("192.168.1.7")));
        assertFalse(list.isTrusted(at("192.168.1.8")));
        assertTrue(list.isTrusted(at("172.31.255.255")), "/12 is not byte aligned");
        assertFalse(list.isTrusted(at("172.32.0.1")));
        assertFalse(list.isTrusted(at("203.0.113.5")));
    }

    @Test
    void ipv6RangesAndNoCrossFamilyMatch() {
        AllowList list = AllowList.parse("2001:db8::/32,::1");
        assertTrue(list.isTrusted(at("2001:db8:abcd::42")));
        assertTrue(list.isTrusted(at("::1")));
        assertFalse(list.isTrusted(at("2001:db9::1")));
        assertFalse(AllowList.parse("0.0.0.0/0").isTrusted(at("2001:db8::1")), "IPv4 range never matches IPv6");
        assertTrue(AllowList.parse("0.0.0.0/0").isTrusted(at("203.0.113.5")));
    }

    @Test
    void usersComeFromEvidence() {
        AllowList list = AllowList.parse("user:backup");
        Finding f = new Finding("ssh", "203.0.113.5", "NET-003", 30, "odd hour", Map.of("user", "backup"), Instant.now());
        assertTrue(list.isTrusted(f));
        assertFalse(list.isTrusted(at("203.0.113.5")));
    }

    @Test
    void badEntriesAndHostnamesAreIgnoredWithoutDns() {
        AllowList list = AllowList.parse("example.com, 10.0.0.0/33, 999.1.1.1, user:, 10.0.0.0/x, ,1.2.3.4");
        assertEquals(1, list.size(), "only 1.2.3.4 is valid");
        assertFalse(list.isTrusted(at("example.com")), "a hostname target is never resolved");
        assertEquals(0, AllowList.parse(null).size());
    }

    private static Finding at(String target) {
        return new Finding("ssh", target, "NET-001", 70, "x");
    }
}
