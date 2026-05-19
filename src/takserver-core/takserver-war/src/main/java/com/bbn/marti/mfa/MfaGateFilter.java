package com.bbn.marti.mfa;

import java.io.IOException;
import java.security.Principal;
import java.util.Set;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Gate that forces every password-authenticated user hitting /Marti/** to
 * complete TOTP before any other admin endpoint responds. The filter is
 * slotted into the Spring Security filter chain via security-context.xml's
 * &lt;sec:custom-filter ref="mfaGateFilter" after="LAST_FILTER" /&gt;. It is
 * deliberately NOT registered with the servlet container directly — an
 * earlier FilterRegistrationBean-based wiring made the servlet container
 * block on bean init long enough that port 8443 never opened and ECS
 * health-checks SIGKILLed the container.
 *
 * Decision table once authenticated:
 *   1. Path is on the MFA whitelist (the MFA pages and the MFA API itself
 *      have to be reachable, otherwise the user can never satisfy the gate)
 *      => pass through.
 *   2. Session already stamped mfa_verified=true => pass through.
 *   3. User row exists and is enrolled => 302 to /Marti/mfa/verify.html
 *      preserving the original URL in the "next" query string.
 *   4. No row OR not yet enrolled => 302 to /Marti/mfa/enroll.html.
 *
 * Cert-authenticated requests (X509 principal) intentionally skip the
 * gate — the cert itself is the second factor for those flows.
 */
public class MfaGateFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(MfaGateFilter.class);

	// Whitelist of suffixes/exact paths that must remain reachable so the
	// gate is satisfiable. Kept narrow on purpose so an unrelated endpoint
	// cannot be brought under /Marti/mfa to bypass the gate.
	private static final Set<String> WHITELIST_PREFIXES = Set.of(
			"/Marti/mfa/",
			"/Marti/api/mfa/",
			"/Marti/login/",
			"/Marti/css/",
			"/Marti/jquery/",
			"/Marti/lib/",
			"/Marti/images/",
			"/Marti/fonts/",
			"/Marti/favicon.ico",
			"/Marti/menubar.html",
			"/Marti/footer.jsp");

	private final MfaService mfaService;

	public MfaGateFilter(MfaService mfaService) {
		this.mfaService = mfaService;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest http = (HttpServletRequest) req;
		HttpServletResponse hresp = (HttpServletResponse) resp;
		String path = http.getRequestURI();

		// Only gate /Marti/** — federation, oauth and sync APIs are out of scope.
		if (path == null || !path.startsWith("/Marti")) {
			chain.doFilter(req, resp);
			return;
		}
		for (String wl : WHITELIST_PREFIXES) {
			if (path.startsWith(wl) || path.equals(wl)) {
				chain.doFilter(req, resp);
				return;
			}
		}

		Principal principal = http.getUserPrincipal();
		if (principal == null) {
			chain.doFilter(req, resp);
			return;
		}

		// Note: an earlier version skipped the gate when an X.509 attribute
		// was present, on the theory that the cert was already the second
		// factor. That broke admin web logins — the admin-proxy nginx
		// sidecar presents its own service cert to the API on port 8446,
		// so every password-authenticated browser session also carries the
		// X.509 attribute. The skip caused MFA to be bypassed for every
		// real admin user. Pure-cert clients hit the data APIs on 8443 and
		// don't reach /Marti/** admin URLs, so always enforcing the gate
		// here is safe.

		HttpSession session = http.getSession(false);
		if (session != null && Boolean.TRUE.equals(session.getAttribute(MfaApi.SESSION_MFA_VERIFIED))) {
			chain.doFilter(req, resp);
			return;
		}

		String username = principal.getName();
		try {
			var row = mfaService.findByUsername(username);
			String next = http.getRequestURI();
			String qs = http.getQueryString();
			if (qs != null && !qs.isEmpty()) {
				next = next + "?" + qs;
			}
			String redirect = (row.isPresent() && row.get().enrolled)
					? "/Marti/mfa/verify.html?next=" + java.net.URLEncoder.encode(next, "UTF-8")
					: "/Marti/mfa/enroll.html?next=" + java.net.URLEncoder.encode(next, "UTF-8");
			hresp.sendRedirect(redirect);
		} catch (Exception e) {
			logger.error("mfa gate failure for {}", username, e);
			hresp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "mfa gate failure");
		}
	}
}
