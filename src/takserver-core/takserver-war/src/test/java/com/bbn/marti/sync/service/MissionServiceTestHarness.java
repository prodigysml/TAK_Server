package com.bbn.marti.sync.service;

import static org.mockito.Mockito.mock;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.Map;

import com.bbn.marti.config.Configuration;
import com.bbn.marti.remote.config.CoreConfigFacade;

/**
 * Reusable unit-test harness for {@link MissionServiceDefaultImpl}.
 *
 * <p>The production service is a ~5,000-line Spring {@code @Service} wired via a
 * single 28-arg constructor and a {@code getMissionService()} self-proxy backed
 * by a private static field. That coupling is why it historically had zero unit
 * coverage. This harness makes it testable WITHOUT a Spring context or Ignite:
 *
 * <ul>
 *   <li>reflectively builds the service from Mockito mocks (one per constructor
 *       parameter), so the harness auto-adapts if the constructor changes;</li>
 *   <li>installs a mockable {@link MissionService} into the static self-proxy
 *       field, so internal {@code getMissionService().foo()} calls land on a
 *       stub/verify seam rather than re-entering real code;</li>
 *   <li>installs the {@link CoreConfigFacade} test seam so no Ignite boot
 *       occurs (see commit 982d7da3).</li>
 * </ul>
 *
 * <p>Every later cluster (pagination, rowcount checks, cache, races) reuses this
 * to pin current behavior before refactoring. Call {@link #tearDown()} in an
 * {@code @After} to avoid leaking the static singletons between tests.
 */
public final class MissionServiceTestHarness {

	/** Real service instance under test (entry methods run real code). */
	public final MissionServiceDefaultImpl service;

	/** Mock returned by the service's internal {@code getMissionService()}. */
	public final MissionService self;

	private final Map<Class<?>, Object> mocksByType;

	private MissionServiceTestHarness(MissionServiceDefaultImpl service, MissionService self,
			Map<Class<?>, Object> mocksByType) {
		this.service = service;
		this.self = self;
		this.mocksByType = mocksByType;
	}

	public static MissionServiceTestHarness create() {
		try {
			// Avoid Ignite boot for any CoreConfig reads on the code paths under test.
			CoreConfigFacade.setInstanceForTesting(new Configuration());

			Constructor<?> ctor = widestConstructor(MissionServiceDefaultImpl.class);
			ctor.setAccessible(true);

			Class<?>[] paramTypes = ctor.getParameterTypes();
			Map<Class<?>, Object> mocksByType = new LinkedHashMap<>();
			Object[] args = new Object[paramTypes.length];
			for (int i = 0; i < paramTypes.length; i++) {
				Object m = mock(paramTypes[i]);
				args[i] = m;
				// Constructor parameter types are distinct in this service; key by type for lookup.
				mocksByType.put(paramTypes[i], m);
			}

			MissionServiceDefaultImpl service = (MissionServiceDefaultImpl) ctor.newInstance(args);

			MissionService self = mock(MissionService.class);
			setSelfProxy(self);

			return new MissionServiceTestHarness(service, self, mocksByType);
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			throw new RuntimeException("failed to build MissionServiceDefaultImpl test harness", e);
		}
	}

	/** Returns the Mockito mock that was injected for the given constructor parameter type. */
	@SuppressWarnings("unchecked")
	public <T> T mockOf(Class<T> type) {
		Object m = mocksByType.get(type);
		if (m == null) {
			throw new IllegalArgumentException("no constructor-injected mock of type " + type.getName());
		}
		return (T) m;
	}

	/** Clears the static singletons so they do not leak into later tests. */
	public static void tearDown() {
		try {
			setSelfProxy(null);
		} catch (Exception ignored) {
			// best effort
		}
		CoreConfigFacade.clearInstanceForTesting();
	}

	private static void setSelfProxy(MissionService value) throws Exception {
		Field f = MissionServiceDefaultImpl.class.getDeclaredField("missionService");
		f.setAccessible(true);
		f.set(null, value);
	}

	private static Constructor<?> widestConstructor(Class<?> c) {
		Constructor<?> best = null;
		for (Constructor<?> k : c.getDeclaredConstructors()) {
			if (best == null || k.getParameterCount() > best.getParameterCount()) {
				best = k;
			}
		}
		if (best == null) {
			throw new IllegalStateException("no constructor on " + c.getName());
		}
		return best;
	}
}
