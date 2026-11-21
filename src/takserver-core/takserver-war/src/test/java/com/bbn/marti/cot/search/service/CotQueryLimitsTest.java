package com.bbn.marti.cot.search.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

public class CotQueryLimitsTest {

    @Test
    public void omittedMaximumResultsGetsDefault() {
        assertEquals(10_000, CotQueryLimits.clampMaximumResults(null));
    }

    @Test
    public void normalMaximumResultsIsKept() {
        assertEquals(1, CotQueryLimits.clampMaximumResults(1));
        assertEquals(500, CotQueryLimits.clampMaximumResults(500));
        assertEquals(100_000, CotQueryLimits.clampMaximumResults(100_000));
    }

    @Test
    public void hugeMaximumResultsIsClamped() {
        assertEquals(100_000, CotQueryLimits.clampMaximumResults(100_001));
        assertEquals(100_000, CotQueryLimits.clampMaximumResults(Integer.MAX_VALUE));
    }

    @Test
    public void deliveryToRequestingClientIsAllowed() {
        assertEquals("203.0.113.7", CotQueryLimits.validateDeliveryTarget("203.0.113.7", 8087, "203.0.113.7"));
        assertEquals("10.1.2.3", CotQueryLimits.validateDeliveryTarget("10.1.2.3", 1024, "10.1.2.3"));
        assertEquals("2001:db8:0:0:0:0:0:1", CotQueryLimits.validateDeliveryTarget("2001:db8::1", 65535, "2001:db8::1"));
    }

    @Test
    public void deliveryToAnotherHostIsRejected() {
        assertRejected("198.51.100.1", 8087, "203.0.113.7");
        assertRejected("10.0.0.5", 8087, "203.0.113.7");
    }

    @Test
    public void localAndMulticastTargetsAreRejected() {
        assertRejected("127.0.0.1", 8087, "127.0.0.1");
        assertRejected("::1", 8087, "::1");
        assertRejected("169.254.169.254", 8087, "169.254.169.254");
        assertRejected("0.0.0.0", 8087, "0.0.0.0");
        assertRejected("224.0.0.1", 8087, "224.0.0.1");
        assertRejected("fe80::1", 8087, "fe80::1");
    }

    @Test
    public void privilegedAndInvalidPortsAreRejected() {
        assertRejected("203.0.113.7", 0, "203.0.113.7");
        assertRejected("203.0.113.7", 22, "203.0.113.7");
        assertRejected("203.0.113.7", 1023, "203.0.113.7");
        assertRejected("203.0.113.7", 65536, "203.0.113.7");
        assertRejected("203.0.113.7", -1, "203.0.113.7");
    }

    @Test
    public void missingValuesAreRejected() {
        assertRejected(null, 8087, "203.0.113.7");
        assertRejected("", 8087, "203.0.113.7");
        assertRejected("203.0.113.7", 8087, null);
    }

    private static void assertRejected(String host, int port, String remote) {
        try {
            CotQueryLimits.validateDeliveryTarget(host, port, remote);
            fail("expected rejection of " + host + ":" + port + " from " + remote);
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }
}
