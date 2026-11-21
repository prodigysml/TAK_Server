package com.bbn.marti.device.profile.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * Limits on profile tool file requests: duplicate relative paths are collapsed,
 * and every loaded file counts against a per-file and per-request byte budget.
 */
public class ProfileServiceContentLimitTest {

	@Test
	public void duplicatesCollapsedInOrder() {
		List<String> paths = ProfileService.dedupeRelativePaths(new String[] { "/a", "/b", "/a", "/a", "/c", "/b" });
		assertEquals(Arrays.asList("/a", "/b", "/c"), paths);
	}

	@Test
	public void nullPathsGiveEmptyList() {
		assertTrue(ProfileService.dedupeRelativePaths(null).isEmpty());
	}

	@Test
	public void manyCopiesOfOnePathCountOnce() {
		String[] paths = new String[10_000];
		Arrays.fill(paths, "/big.bin");
		List<String> unique = ProfileService.dedupeRelativePaths(paths);
		assertEquals(1, unique.size());
		assertTrue(unique.size() <= ProfileService.MAX_RELATIVE_PATHS);
	}

	@Test
	public void distinctPathsOverCapDetectable() {
		String[] paths = new String[ProfileService.MAX_RELATIVE_PATHS + 1];
		for (int i = 0; i < paths.length; i++) {
			paths[i] = "/f" + i;
		}
		assertTrue(ProfileService.dedupeRelativePaths(paths).size() > ProfileService.MAX_RELATIVE_PATHS);
	}

	@Test
	public void defaultPathCapIsReasonable() {
		assertTrue(ProfileService.MAX_RELATIVE_PATHS >= 1);
		assertTrue(ProfileService.MAX_RELATIVE_PATHS <= 10_000);
	}

	@Test
	public void filesWithinBudgetAccepted() {
		ProfileService.ContentSizeBudget budget = new ProfileService.ContentSizeBudget(100, 250);
		budget.reserve(100);
		budget.reserve(100);
		budget.reserve(50);
		assertEquals(250, budget.getUsedBytes());
	}

	@Test
	public void singleFileOverPerFileLimitRejected() {
		ProfileService.ContentSizeBudget budget = new ProfileService.ContentSizeBudget(100, 1000);
		assertTooLarge(budget, 101);
		assertEquals(0, budget.getUsedBytes());
	}

	@Test
	public void runningTotalOverLimitRejected() {
		// e.g. a directory of many files each under the per-file limit
		ProfileService.ContentSizeBudget budget = new ProfileService.ContentSizeBudget(100, 250);
		budget.reserve(100);
		budget.reserve(100);
		assertTooLarge(budget, 51);
		assertEquals(200, budget.getUsedBytes());
	}

	private static void assertTooLarge(ProfileService.ContentSizeBudget budget, long length) {
		try {
			budget.reserve(length);
			fail("expected ContentTooLargeException");
		} catch (ProfileService.ContentTooLargeException expected) {
			// mapped to 413 by getProfileDirectoryContent
		}
	}
}
