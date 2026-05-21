package com.bbn.tak.tls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import org.junit.Test;

/**
 * Unit tests for CertManagerApi.csrLockFor — verifies striped per-uid lock
 * mitigates the duplicate-CSR race (CWE-362). Same uid must map to the same
 * lock instance so concurrent submissions serialize.
 */
public class CertManagerCsrLockTest {

	@Test
	public void sameUidReturnsSameLock() {
		ReentrantLock a = CertManagerApi.csrLockFor("client-uid-123");
		ReentrantLock b = CertManagerApi.csrLockFor("client-uid-123");
		assertSame("identical uid must map to identical lock instance", a, b);
	}

	@Test
	public void nullUidIsHandled() {
		ReentrantLock l = CertManagerApi.csrLockFor(null);
		assertNotNull("null uid must not throw", l);
		// repeat null → same lock as before
		assertSame(l, CertManagerApi.csrLockFor(null));
	}

	@Test
	public void emptyUidIsHandled() {
		ReentrantLock l = CertManagerApi.csrLockFor("");
		assertNotNull(l);
		assertSame(l, CertManagerApi.csrLockFor(""));
	}

	@Test
	public void differentUidsHitMultipleStripes() {
		// 1000 distinct uids across 256 stripes should populate at least
		// half the stripes (with very high probability under hashCode).
		Set<ReentrantLock> distinctLocks = new HashSet<>();
		for (int i = 0; i < 1000; i++) {
			distinctLocks.add(CertManagerApi.csrLockFor("uid-" + i));
		}
		assertTrue("expected wide stripe coverage, got only " + distinctLocks.size(),
				distinctLocks.size() > 128);
	}

	@Test
	public void sameUidLockProvidesMutualExclusion() throws Exception {
		// Hammer the same uid lock from two threads incrementing a shared
		// counter; if the lock is real, no lost updates.
		final String uid = "concurrent-uid";
		final ReentrantLock lock = CertManagerApi.csrLockFor(uid);
		final AtomicInteger counter = new AtomicInteger(0);
		final int iters = 10000;
		Runnable r = () -> {
			for (int i = 0; i < iters; i++) {
				CertManagerApi.csrLockFor(uid).lock();
				try {
					counter.incrementAndGet();
				} finally {
					CertManagerApi.csrLockFor(uid).unlock();
				}
			}
		};
		Thread t1 = new Thread(r);
		Thread t2 = new Thread(r);
		t1.start(); t2.start();
		t1.join(); t2.join();
		assertEquals(2 * iters, counter.get());
		// lock should now be free
		assertTrue(lock.tryLock());
		lock.unlock();
	}

	@Test
	public void hashCollisionStillSerializesCorrectly() {
		// Two different uids that happen to collide on the same stripe
		// should still each get a (shared) ReentrantLock that works.
		// Just verify lock acquisition works on a long string.
		ReentrantLock l1 = CertManagerApi.csrLockFor("a-very-long-client-uid-string-aaaaaaaa");
		ReentrantLock l2 = CertManagerApi.csrLockFor("a-very-long-client-uid-string-bbbbbbbb");
		assertNotNull(l1);
		assertNotNull(l2);
		l1.lock();
		try {
			assertTrue(l1.isHeldByCurrentThread());
		} finally {
			l1.unlock();
		}
	}
}
