package tak.server.federation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Comparator;
import java.util.concurrent.ConcurrentSkipListSet;

import org.junit.Test;

/**
 * Unit tests for GuardedStreamHolder.addToCacheBounded — verifies the
 * unbounded-growth DoS fix (CWE-400). A malicious federate previously could
 * flood the broker's per-stream cache, which is replayed in full to every
 * newly attached outbound stream.
 */
public class GuardedStreamHolderBoundedCacheTest {

	@Test
	public void addsUpToCap() {
		ConcurrentSkipListSet<Integer> cache = new ConcurrentSkipListSet<>(Comparator.naturalOrder());
		for (int i = 0; i < 100; i++) {
			assertTrue(GuardedStreamHolder.addToCacheBounded(cache, i, 100));
		}
		assertEquals(100, cache.size());
	}

	@Test
	public void evictsLowestWhenOverCap() {
		ConcurrentSkipListSet<Integer> cache = new ConcurrentSkipListSet<>(Comparator.naturalOrder());
		// fill cache to cap with 1..5
		for (int i = 1; i <= 5; i++) {
			GuardedStreamHolder.addToCacheBounded(cache, i, 5);
		}
		assertEquals(5, cache.size());
		// add 6 → should evict 1 (lowest)
		GuardedStreamHolder.addToCacheBounded(cache, 6, 5);
		assertEquals(5, cache.size());
		assertFalse("oldest entry must have been evicted", cache.contains(1));
		assertTrue(cache.contains(6));
	}

	@Test
	public void floodOnlyKeepsCapManyEntries() {
		ConcurrentSkipListSet<Integer> cache = new ConcurrentSkipListSet<>(Comparator.naturalOrder());
		final int cap = 50;
		// simulate malicious flood of 10_000 events
		for (int i = 0; i < 10_000; i++) {
			GuardedStreamHolder.addToCacheBounded(cache, i, cap);
		}
		assertEquals("cache must never exceed cap regardless of input volume",
				cap, cache.size());
	}

	@Test
	public void nullEventIsRejected() {
		ConcurrentSkipListSet<Integer> cache = new ConcurrentSkipListSet<>(Comparator.naturalOrder());
		assertFalse(GuardedStreamHolder.addToCacheBounded(cache, null, 10));
		assertEquals(0, cache.size());
	}

	@Test
	public void duplicateEventDoesNotGrow() {
		ConcurrentSkipListSet<Integer> cache = new ConcurrentSkipListSet<>(Comparator.naturalOrder());
		GuardedStreamHolder.addToCacheBounded(cache, 42, 10);
		assertFalse("dup must return false (Set semantics)",
				GuardedStreamHolder.addToCacheBounded(cache, 42, 10));
		assertEquals(1, cache.size());
	}

	@Test
	public void capOfOneKeepsOnlyLatest() {
		ConcurrentSkipListSet<Integer> cache = new ConcurrentSkipListSet<>(Comparator.naturalOrder());
		for (int i = 0; i < 100; i++) {
			GuardedStreamHolder.addToCacheBounded(cache, i, 1);
		}
		assertEquals(1, cache.size());
		assertTrue(cache.contains(99));
	}

	@Test
	public void maxCacheSizeConstantExists() {
		// document the public constant the helper guards by
		assertTrue("MAX_CACHE_SIZE must be positive", GuardedStreamHolder.MAX_CACHE_SIZE > 0);
	}
}
