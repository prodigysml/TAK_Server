package tak.server.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Evaluates the FilterSecurityInterceptor intercept-url rules in
 * security-context.xml the way Spring does: first matching ant rule wins,
 * then RoleHierarchyVoter grants if the caller holds (directly or through the
 * hierarchy) any listed role.
 *
 * Callers:
 *  - unauthenticated on 8446/8447: pre-authenticated with only
 *    ROLE_NO_CLIENT_CERT (+ ROLE_ALLOW_LOGIN), which Spring counts as fully
 *    authenticated;
 *  - any client-cert / password user: ROLE_ANONYMOUS (+ NON_ADMIN_UI, WEBTAK).
 */
public class SecurityContextRulesTest {

	private static final String[] UNAUTH_8446 = { "ROLE_NO_CLIENT_CERT", "ROLE_ALLOW_LOGIN" };
	private static final String[] CERT_USER = { "ROLE_ANONYMOUS", "ROLE_NON_ADMIN_UI", "ROLE_WEBTAK" };
	private static final String[] ADMIN = { "ROLE_ADMIN", "ROLE_ANONYMOUS" };

	private static final String[] METHODS = { "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS" };

	static class Rule {
		String pattern;
		String method;
		Set<String> access = new HashSet<>();
		AntPathRequestMatcher matcher;
		int index;
	}

	private static final List<Rule> rules = new ArrayList<>();
	private static RoleHierarchyImpl hierarchy;

	@BeforeClass
	public static void load() throws Exception {
		DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
		f.setNamespaceAware(true);
		Document doc;
		try (InputStream xml = SecurityContextRulesTest.class.getResourceAsStream("/security-context.xml")) {
			doc = f.newDocumentBuilder().parse(xml);
		}

		NodeList nl = doc.getElementsByTagNameNS("http://www.springframework.org/schema/security", "intercept-url");
		for (int i = 0; i < nl.getLength(); i++) {
			Element e = (Element) nl.item(i);
			Rule r = new Rule();
			r.index = i;
			r.pattern = e.getAttribute("pattern");
			r.method = e.getAttribute("method").isEmpty() ? null : e.getAttribute("method");
			for (String a : e.getAttribute("access").split(",")) {
				a = a.trim();
				// UserManagementAuthorizationProvider / LocateAuthorizationProvider return
				// ROLE_NO_CLIENT_CERT when their feature is on: assume the worst case.
				if (a.startsWith("#{")) {
					a = "ROLE_NO_CLIENT_CERT";
				}
				r.access.add(a);
			}
			r.matcher = new AntPathRequestMatcher(r.pattern, r.method);
			rules.add(r);
		}

		NodeList props = doc.getElementsByTagNameNS("http://www.springframework.org/schema/beans", "bean");
		for (int i = 0; i < props.getLength(); i++) {
			Element b = (Element) props.item(i);
			if ("roleHierarchy".equals(b.getAttribute("id"))) {
				String text = b.getElementsByTagNameNS("http://www.springframework.org/schema/beans", "value")
						.item(0).getTextContent();
				hierarchy = RoleHierarchyImpl.fromHierarchy(text.trim().replaceAll("\\s*\\n\\s*", "\n"));
			}
		}
		assertTrue("no rules parsed", rules.size() > 100);
		assertTrue("no role hierarchy parsed", hierarchy != null);
	}

	private static HttpServletRequest req(String method, String path) {
		HttpServletRequest r = mock(HttpServletRequest.class);
		when(r.getMethod()).thenReturn(method);
		when(r.getServletPath()).thenReturn(path);
		when(r.getPathInfo()).thenReturn(null);
		return r;
	}

	static Rule firstMatch(String method, String path) {
		HttpServletRequest r = req(method, path);
		for (Rule rule : rules) {
			if (rule.matcher.matches(r)) {
				return rule;
			}
		}
		return null;
	}

	static boolean granted(String method, String path, String... roles) {
		Rule rule = firstMatch(method, path);
		if (rule == null) {
			return false; // AffirmativeBased denies when every voter abstains
		}
		List<GrantedAuthority> held = new ArrayList<>();
		for (String role : roles) {
			held.add(new SimpleGrantedAuthority(role));
		}
		Collection<? extends GrantedAuthority> reachable = hierarchy.getReachableGrantedAuthorities(held);
		for (GrantedAuthority a : reachable) {
			if (rule.access.contains(a.getAuthority())) {
				return true;
			}
		}
		return false;
	}

	/** turn an ant pattern into one concrete path it matches */
	private static String instantiate(String pattern) {
		return pattern.replace("/**", "/x").replace("**", "x").replace("*", "x");
	}

	@Test
	public void noIsAuthenticatedRules() {
		for (Rule r : rules) {
			for (String a : r.access) {
				assertFalse("IS_AUTHENTICATED_* lets the 8446 ROLE_NO_CLIENT_CERT token through: " + r.pattern,
						a.startsWith("IS_AUTHENTICATED"));
			}
		}
	}

	/**
	 * Every rule an unauthenticated 8446 caller satisfies, for every method and
	 * with and without a trailing slash (Spring MVC trailing-slash matching is on,
	 * ApiConfiguration.configurePathMatch). Anything new here must be reviewed.
	 */
	@Test
	public void unauthenticated8446ReachesOnlyTheExpectedRules() {
		Set<String> expected = new TreeSet<>(List.of(
				"/Marti/api/tls/makeClientKeyStore", "/Marti/api/tls/config", "/Marti/api/tls/signClient",
				"/Marti/api/tls/signClient/v2", "/Marti/api/tls/profile/enrollment", "/Marti/api/tls/profile/tool/**",
				"/Marti/error/**", "/error", "/Marti/jquery/**", "/Marti/lib/**", "/Marti/css/**",
				"/oauth/token", "/oauth/authorize", "/login/**", "/Marti/login/**",
				"/register/**", "/locate/**"));
		Set<String> reached = new TreeSet<>();
		for (Rule r : rules) {
			String p = instantiate(r.pattern);
			for (String m : METHODS) {
				for (String path : new String[] { p, p + "/" }) {
					if (granted(m, path, UNAUTH_8446)) {
						reached.add(firstMatch(m, path).pattern);
					}
				}
			}
		}
		assertEquals(expected, reached);
	}

	/**
	 * Spring MVC matches /foo/ to a /foo handler, but the ant rule /foo does not
	 * match /foo/, so a request with a trailing slash falls through to the next
	 * rule. List every admin rule where that next rule lets a cert user in.
	 */
	@Test
	public void trailingSlashDoesNotWeakenRules() {
		List<String> weaker = new ArrayList<>();
		for (Rule r : rules) {
			if (r.pattern.endsWith("/**") || r.pattern.endsWith("/") || !r.access.contains("ROLE_ADMIN")) {
				continue;
			}
			String p = instantiate(r.pattern);
			for (String m : METHODS) {
				if (r.method != null && !r.method.equals(m)) {
					continue;
				}
				boolean bare = granted(m, p, CERT_USER);
				boolean slash = granted(m, p + "/", CERT_USER);
				if (!bare && slash) {
					weaker.add(m + " " + p + "/ -> " + firstMatch(m, p + "/").pattern);
				}
			}
		}
		assertEquals(KNOWN_TRAILING_SLASH, new TreeSet<>(weaker));
	}

	/*
	 * Known, each closed by @PreAuthorize on the handler:
	 *  - DataFeedApi.getStatsForDataFeed() (all feeds' stats)
	 *  - PropertiesApi.getAllPropertyKeys()
	 */
	private static final Set<String> KNOWN_TRAILING_SLASH = new TreeSet<>(List.of(
			"GET /Marti/api/datafeeds/stats/ -> /Marti/api/datafeeds/**",
			"GET /Marti/api/properties/uids/ -> /Marti/api/properties/**"));

	@RestController
	@RequestMapping("/Marti/api")
	public static class StatsLike {
		@GetMapping("/datafeeds/stats")
		public String stats() {
			return "all-feeds";
		}
	}

	/** ApiConfiguration.configurePathMatch turns trailing-slash matching on: /stats/ reaches the /stats handler. */
	@SuppressWarnings("deprecation")
	@Test
	public void mvcRoutesTrailingSlashToTheSameHandler() throws Exception {
		MockMvc mvc = MockMvcBuilders.standaloneSetup(new StatsLike()).setUseTrailingSlashPatternMatch(true).build();
		mvc.perform(MockMvcRequestBuilders.get("/Marti/api/datafeeds/stats/"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string("all-feeds"));
		// ...while the admin-only intercept-url does not match it
		assertEquals("/Marti/api/datafeeds/**", firstMatch("GET", "/Marti/api/datafeeds/stats/").pattern);
		assertTrue(granted("GET", "/Marti/api/datafeeds/stats/", CERT_USER));
	}

	/** the handler-level checks that close the trailing-slash gaps above and the /files/api gap */
	@Test
	public void handlersCarryAdminPreAuthorize() throws Exception {
		assertAdmin(com.bbn.marti.feeds.DataFeedApi.class.getMethod("getStatsForDataFeed"));
		assertAdmin(com.bbn.marti.sync.api.PropertiesApi.class.getMethod("getAllPropertyKeys"));
		assertAdmin(com.bbn.file.FileConfigurationApi.class.getMethod("setFileConfiguration",
				com.bbn.file.FileConfigurationModel.class));
	}

	private static void assertAdmin(Method m) {
		PreAuthorize ann = m.getAnnotation(PreAuthorize.class);
		assertTrue("missing @PreAuthorize on " + m, ann != null);
		assertEquals("hasRole('ROLE_ADMIN')", ann.value());
	}

	@Test
	public void dataFeedStatsListIsAdminOnlyAtRuleLevel() {
		assertFalse(granted("GET", "/Marti/api/datafeeds/stats", CERT_USER));
		assertTrue(granted("GET", "/Marti/api/datafeeds/stats", ADMIN));
		assertFalse(granted("GET", "/Marti/api/datafeeds/stats", UNAUTH_8446));
	}

	@Test
	public void fileConfigRuleLevel() {
		// /files/api/** has no rule of its own; it falls to /** ROLE_ANONYMOUS, so
		// FileConfigurationApi.setFileConfiguration needs its own admin check.
		assertFalse(granted("POST", "/files/api/config", UNAUTH_8446));
		assertEquals("/**", firstMatch("POST", "/files/api/config").pattern);
	}
}
