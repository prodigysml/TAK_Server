package tak.server.cache;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.cache.Cache;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.cache.interceptor.CacheEvictOperation;
import org.springframework.cache.interceptor.CacheOperationInvocationContext;

import com.bbn.marti.config.Cluster;
import com.bbn.marti.config.Configuration;
import com.bbn.marti.remote.config.CoreConfigFacade;
import com.bbn.marti.sync.model.Mission;
import com.bbn.marti.sync.repository.MissionRepository;
import com.bbn.marti.sync.service.MissionService;

import tak.server.cache.resolvers.MissionCacheResolver;
import tak.server.cache.resolvers.TakCacheManagerResolver;

/**
 * A mission change (such as a new password) evicts the mission's cache through
 * {@link MissionCacheResolver}, which names the cache by the lowercased mission name.
 * {@link MissionCacheHelper} used to cache under the name as typed, so for a mission
 * with a capital letter the eviction missed and the old copy, still without its
 * password, kept being served until it expired.
 */
public class MissionCacheEvictionTest {

	private final CaffeineCacheManager cacheManager = new CaffeineCacheManager();
	private MissionCacheHelper helper;
	private MissionRepository missionRepository;
	private MissionCacheResolver resolver;

	@Before
	public void setUp() throws Exception {
		Configuration configuration = new Configuration();
		Cluster cluster = new Cluster();
		cluster.setEnabled(false);
		configuration.setCluster(cluster);
		CoreConfigFacade.setInstanceForTesting(configuration);

		helper = new MissionCacheHelper();
		missionRepository = mock(MissionRepository.class);
		set(MissionCacheHelper.class, helper, "caffineCacheManager", cacheManager);
		set(MissionCacheHelper.class, helper, "missionRepository", missionRepository);
		set(MissionCacheHelper.class, helper, "missionService", mock(MissionService.class));

		resolver = new MissionCacheResolver();
		set(TakCacheManagerResolver.class, resolver, "caffineCacheManager", cacheManager);
	}

	@After
	public void tearDown() {
		CoreConfigFacade.clearInstanceForTesting();
	}

	private static void set(Class<?> owner, Object target, String field, Object value) throws Exception {
		Field f = owner.getDeclaredField(field);
		f.setAccessible(true);
		f.set(target, value);
	}

	private static Mission mission(String name, String passwordHash) {
		Mission m = new Mission();
		m.setName(name);
		m.setPasswordHash(passwordHash);
		return m;
	}

	/** Clears every cache the resolver names for invalidateMissionCache(name), as @CacheEvict(allEntries) does. */
	private void evictLikeInvalidateMissionCache(String name) throws Exception {
		CacheOperationInvocationContext<?> context = mock(CacheOperationInvocationContext.class);
		when(context.getArgs()).thenReturn(new Object[] { name });
		when(context.getMethod()).thenReturn(MissionService.class.getMethod("invalidateMissionCache", String.class));
		doReturn(new CacheEvictOperation.Builder().build()).when(context).getOperation();
		for (Cache cache : resolver.resolveCaches(context)) {
			cache.clear();
		}
	}

	@Test
	public void passwordChangeOnMixedCaseMissionIsSeenAfterEviction() throws Exception {
		String name = "OP UNO";
		when(missionRepository.getByNameNoCache(name))
				.thenReturn(mission(name, null))
				.thenReturn(mission(name, "$2a$10$newhash"));

		// first read caches the mission without a password
		assertNull(helper.getMission(name, true, false).getPasswordHash());

		// setPassword updates the row, then invalidates the cache by name
		evictLikeInvalidateMissionCache(name);

		assertEquals("$2a$10$newhash", helper.getMission(name, true, false).getPasswordHash());
	}

	@Test
	public void cacheNameIsLowercased() {
		assertEquals("op uno", MissionCacheHelper.getCacheName("OP UNO"));
	}
}
