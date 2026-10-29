package com.bbn.marti.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Answers;

import com.bbn.marti.config.Configuration;
import com.bbn.marti.remote.config.CoreConfigFacade;
import com.bbn.marti.remote.groups.User;

import jakarta.xml.bind.JAXBContext;

/**
 * Tests DistributedSubscriptionManager.setUserForSubscriptionIfAbsent.
 *
 * <p>X509 auth on a streaming connection finishes on its own thread, so it races
 * the connection's subscription being created. Both sides call this method and
 * only the first may attach the user (and then send latest SA and start protocol
 * negotiation). When neither attached it, the subscription kept no user and the
 * device could not join a mission by its UID.
 */
public class SubscriptionUserIfAbsentTest {

	private DistributedSubscriptionManager manager;

	// Loading Subscription reads CoreConfig. Install the example config so that
	// doesn't boot Ignite.
	@BeforeClass
	public static void installConfig() throws Exception {
		Configuration config = (Configuration) JAXBContext.newInstance(Configuration.class)
				.createUnmarshaller().unmarshal(new File("example/CoreConfig.example.xml"));
		CoreConfigFacade.setInstanceForTesting(config);
	}

	@AfterClass
	public static void clearConfig() {
		CoreConfigFacade.clearInstanceForTesting();
	}

	// Subscription's constructor joins the Ignite cluster; skip it, keep the real accessors.
	private static Subscription newSubscription() {
		return mock(Subscription.class, withSettings().defaultAnswer(Answers.CALLS_REAL_METHODS));
	}

	@Before
	public void setUp() {
		manager = spy(new DistributedSubscriptionManager());
		// the real method also indexes the subscription in the Ignite-backed store
		doAnswer(inv -> {
			Subscription s = inv.getArgument(1);
			s.setUser(inv.getArgument(0));
			return s;
		}).when(manager).setUserForSubscription(any(), any());
	}

	@Test
	public void attachesUserToSubscriptionWithoutOne() {
		Subscription sub = newSubscription();
		User user = mock(User.class);

		assertTrue(manager.setUserForSubscriptionIfAbsent(user, sub));
		assertSame(user, sub.getUser());
	}

	@Test
	public void leavesExistingUserAlone() {
		Subscription sub = newSubscription();
		User first = mock(User.class);
		sub.setUser(first);

		assertFalse(manager.setUserForSubscriptionIfAbsent(mock(User.class), sub));
		assertSame(first, sub.getUser());
		verify(manager, never()).setUserForSubscription(any(), any());
	}

	@Test
	public void ignoresNulls() {
		assertFalse(manager.setUserForSubscriptionIfAbsent(null, newSubscription()));
		assertFalse(manager.setUserForSubscriptionIfAbsent(mock(User.class), null));
		verify(manager, never()).setUserForSubscription(any(), any());
	}

	@Test
	public void onlyOneOfTwoRacingCallersAttaches() throws Exception {
		ExecutorService pool = Executors.newFixedThreadPool(2);
		try {
			for (int round = 0; round < 200; round++) {
				Subscription sub = newSubscription();
				User user = mock(User.class);
				CountDownLatch go = new CountDownLatch(1);
				Future<Boolean> a = pool.submit(() -> { go.await(); return manager.setUserForSubscriptionIfAbsent(user, sub); });
				Future<Boolean> b = pool.submit(() -> { go.await(); return manager.setUserForSubscriptionIfAbsent(user, sub); });
				go.countDown();
				int attached = (a.get(5, TimeUnit.SECONDS) ? 1 : 0) + (b.get(5, TimeUnit.SECONDS) ? 1 : 0);
				assertEquals("round " + round, 1, attached);
				assertSame(user, sub.getUser());
			}
		} finally {
			pool.shutdownNow();
		}
	}
}
