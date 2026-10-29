package tak.server.federation.hub.broker;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.atakmap.Tak.ROL;

/**
 * ROL that arrives before a session's ROL stream is registered is cached in
 * HubConnectionStore. A federate that never registers the stream used to be
 * able to grow that cache without limit; it is now capped per session.
 */
public class HubConnectionStoreRolCacheTest {

	private static ROL rol(String program) {
		return ROL.newBuilder().setProgram(program).build();
	}

	@Test
	public void capsCountPerSession() {
		HubConnectionStore store = new HubConnectionStore();
		for (int i = 0; i < 3; i++) {
			assertTrue(store.cacheRol(rol("p" + i), 10, "s1", 3, Long.MAX_VALUE));
		}
		assertFalse(store.cacheRol(rol("p3"), 10, "s1", 3, Long.MAX_VALUE));
		// another session has its own allowance
		assertTrue(store.cacheRol(rol("q"), 10, "s2", 3, Long.MAX_VALUE));
	}

	@Test
	public void capsBytesPerSession() {
		HubConnectionStore store = new HubConnectionStore();
		ROL first = rol("first");
		assertTrue(store.cacheRol(first, first.getSerializedSize(), "s1", 100, first.getSerializedSize() + 4));
		ROL big = rol("a program that does not fit");
		assertFalse(store.cacheRol(big, big.getSerializedSize(), "s1", 100, first.getSerializedSize() + 4));
	}

	@Test
	public void clearingTheSessionFreesItsAllowance() {
		HubConnectionStore store = new HubConnectionStore();
		assertTrue(store.cacheRol(rol("a"), 10, "s1", 1, Long.MAX_VALUE));
		assertFalse(store.cacheRol(rol("b"), 10, "s1", 1, Long.MAX_VALUE));
		store.clearIdFromAllStores("s1");
		assertTrue(store.cacheRol(rol("c"), 10, "s1", 1, Long.MAX_VALUE));
	}
}
