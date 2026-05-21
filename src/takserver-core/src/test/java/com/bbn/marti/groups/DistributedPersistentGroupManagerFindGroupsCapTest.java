package com.bbn.marti.groups;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Bounds the findGroups(List<String>) defense-in-depth cap. Each unresolved
 * name triggers hydrateGroup which may write to the group table via
 * groupDao().save() (CWE-400, CWE-770). Without a cap, callers that forgot
 * their own size guard could amplify a single request into thousands of
 * DB writes.
 */
public class DistributedPersistentGroupManagerFindGroupsCapTest {

	@Test
	public void zeroIsAccepted() {
		assertFalse(DistributedPersistentGroupManager.shouldRejectFindGroupsList(0, 1024));
	}

	@Test
	public void atCapAccepted() {
		assertFalse(DistributedPersistentGroupManager.shouldRejectFindGroupsList(1024, 1024));
	}

	@Test
	public void oneOverRejected() {
		assertTrue(DistributedPersistentGroupManager.shouldRejectFindGroupsList(1025, 1024));
	}

	@Test
	public void floodRejected() {
		assertTrue(DistributedPersistentGroupManager.shouldRejectFindGroupsList(1_000_000, 1024));
	}

	@Test
	public void defaultCapIsReasonable() {
		assertTrue(DistributedPersistentGroupManager.MAX_FIND_GROUPS_NAMES >= 64);
		assertTrue(DistributedPersistentGroupManager.MAX_FIND_GROUPS_NAMES <= 100_000);
	}
}
