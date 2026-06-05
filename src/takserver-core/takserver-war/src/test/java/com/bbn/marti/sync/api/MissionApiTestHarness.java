package com.bbn.marti.sync.api;

import static org.mockito.Mockito.mock;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import com.bbn.marti.config.Configuration;
import com.bbn.marti.remote.SubscriptionManagerLite;
import com.bbn.marti.remote.config.CoreConfigFacade;
import com.bbn.marti.sync.repository.MissionRepository;
import com.bbn.marti.sync.service.MissionService;
import com.bbn.marti.util.CommonUtil;

/**
 * Reusable unit-test harness for the field-injected {@link MissionApi} controller.
 *
 * <p>MissionApi wires ~17 collaborators via {@code @Autowired} fields and has no
 * constructor, so it cannot be built from mocks the usual way. This harness
 * {@code new}s it and reflectively injects Mockito mocks for the collaborators
 * the endpoints under test actually touch, installing the {@link CoreConfigFacade}
 * no-Ignite seam for safety. Add more fields via {@link #inject} as new MissionApi
 * sites get coverage. Call {@link #tearDown()} in an {@code @After}.
 */
public final class MissionApiTestHarness {

	public final MissionApi api;
	private final Map<String, Object> mocksByField = new HashMap<>();

	private MissionApiTestHarness(MissionApi api) {
		this.api = api;
	}

	public static MissionApiTestHarness create() {
		try {
			CoreConfigFacade.setInstanceForTesting(new Configuration());
			MissionApiTestHarness h = new MissionApiTestHarness(new MissionApi());
			h.inject("missionService", MissionService.class);
			h.inject("missionRepository", MissionRepository.class);
			h.inject("subscriptionManager", SubscriptionManagerLite.class);
			h.inject("martiUtil", CommonUtil.class);
			return h;
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			throw new RuntimeException("failed to build MissionApi test harness", e);
		}
	}

	/** Injects a fresh mock of {@code type} into the named MissionApi field and records it. */
	public <T> T inject(String fieldName, Class<T> type) throws Exception {
		T m = mock(type);
		Field f = MissionApi.class.getDeclaredField(fieldName);
		f.setAccessible(true);
		f.set(api, m);
		mocksByField.put(fieldName, m);
		return m;
	}

	/** Returns the mock previously injected into the named field. */
	@SuppressWarnings("unchecked")
	public <T> T mockField(String fieldName) {
		Object m = mocksByField.get(fieldName);
		if (m == null) {
			throw new IllegalArgumentException("no injected mock for field " + fieldName);
		}
		return (T) m;
	}

	public static void tearDown() {
		CoreConfigFacade.clearInstanceForTesting();
	}
}
