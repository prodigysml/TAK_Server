package tak.server.system;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;

import org.springframework.context.ApplicationContext;

import com.bbn.marti.remote.ServerInfo;

/**
 * Test seam for {@link ApiDependencyProxy}.
 *
 * <p>{@code ApiResponse}'s no-arg constructor calls
 * {@code ApiDependencyProxy.getInstance().serverInfo().getServerId()}, which
 * dereferences a private static {@code ApplicationContext} that is never set in
 * a plain unit test — so any unit test that builds an {@code ApiResponse} NPEs.
 *
 * <p>This installs a mock {@link ApplicationContext} into the proxy so REST-API
 * unit tests can construct {@code ApiResponse} objects without a Spring context.
 * Call {@link #clear()} in an {@code @After} so the static state does not leak
 * into other test classes.
 */
public final class ApiDependencyProxyTestSupport {

	private ApiDependencyProxyTestSupport() {
	}

	/** Installs a stub context whose {@code ServerInfo.getServerId()} returns {@code serverId}. */
	public static void install(String serverId) {
		ApplicationContext ctx = mock(ApplicationContext.class);

		ApiDependencyProxy proxy = new ApiDependencyProxy();
		// setApplicationContext assigns the private static springContext field.
		proxy.setApplicationContext(ctx);

		ServerInfo serverInfo = mock(ServerInfo.class);
		lenient().when(serverInfo.getServerId()).thenReturn(serverId);

		when(ctx.getBean(ApiDependencyProxy.class)).thenReturn(proxy);
		when(ctx.getBean(ServerInfo.class)).thenReturn(serverInfo);
	}

	/** Resets the proxy's static singletons so they do not leak between test classes. */
	public static void clear() {
		setStatic("springContext", null);
		setStatic("instance", null);
	}

	private static void setStatic(String name, Object value) {
		try {
			Field f = ApiDependencyProxy.class.getDeclaredField(name);
			f.setAccessible(true);
			f.set(null, value);
		} catch (ReflectiveOperationException e) {
			throw new RuntimeException("failed to reset ApiDependencyProxy." + name, e);
		}
	}
}
