package com.bbn.marti.sync;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.bbn.marti.sync.api.SubscriptionApi;

/**
 * Bounds the admin /subscriptions/all page-size clamp. SubscriptionStore
 * appends LIMIT and OFFSET directly into the Ignite SQL; without a cap an
 * admin caller can force the server to materialize the entire subscription
 * set in memory (CWE-400).
 */
public class SubscriptionApiLimitClampTest {

	@Test
	public void negativeSentinelClampsToCap() {
		assertEquals(1000, SubscriptionApi.clampSubscriptionLimit(-1, 1000));
	}

	@Test
	public void zeroClampsToCap() {
		assertEquals(1000, SubscriptionApi.clampSubscriptionLimit(0, 1000));
	}

	@Test
	public void smallRequestIsPreserved() {
		assertEquals(25, SubscriptionApi.clampSubscriptionLimit(25, 1000));
	}

	@Test
	public void atCapIsPreserved() {
		assertEquals(1000, SubscriptionApi.clampSubscriptionLimit(1000, 1000));
	}

	@Test
	public void overflowClamped() {
		assertEquals(1000, SubscriptionApi.clampSubscriptionLimit(1_000_000, 1000));
	}

	@Test
	public void defaultCapIsReasonable() {
		assertTrue(SubscriptionApi.MAX_SUBSCRIPTION_PAGE_LIMIT >= 100);
		assertTrue(SubscriptionApi.MAX_SUBSCRIPTION_PAGE_LIMIT <= 100_000);
	}
}
