package com.bbn.marti.mfa;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.junit.Assert.assertTrue;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * The gate after a move to another server: the login token is still valid but
 * this server's session has never seen the user, so the MFA stamp has to come
 * from the shared database.
 */
public class MfaGateFilterTest {

	private MfaService mfaService;
	private MfaGateFilter filter;
	private HttpServletRequest request;
	private HttpServletResponse response;
	private HttpSession session;
	private FilterChain chain;

	@Before
	public void setUp() {
		mfaService = mock(MfaService.class);
		filter = new MfaGateFilter(mfaService, port -> port == 8443);
		request = mock(HttpServletRequest.class);
		response = mock(HttpServletResponse.class);
		session = mock(HttpSession.class);
		chain = mock(FilterChain.class);
		SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
				"alice", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
		when(request.getRequestURI()).thenReturn("/Marti/onboarding/index.html");
		when(request.getMethod()).thenReturn("GET");
		when(request.getHeader("Accept")).thenReturn("text/html");
		when(request.getSession(false)).thenReturn(null);
		when(request.getSession(true)).thenReturn(session);
		when(request.getCookies()).thenReturn(new Cookie[] { new Cookie("access_token", "tok-1") });
		MfaService.MfaRow row = new MfaService.MfaRow();
		row.username = "alice";
		row.enrolled = true;
		when(mfaService.findByUsername("alice")).thenReturn(Optional.of(row));
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void stampFromAnotherServerLetsThePageThrough() throws Exception {
		when(mfaService.isTokenVerified("tok-1", "alice")).thenReturn(true);

		filter.doFilter(request, response, chain);

		verify(chain).doFilter(request, response);
		verify(session).setAttribute(MfaApi.SESSION_MFA_VERIFIED, Boolean.TRUE);
		verify(response, never()).sendRedirect(anyString());
	}

	@Test
	public void noStampSendsTheUserToVerify() throws Exception {
		when(mfaService.isTokenVerified("tok-1", "alice")).thenReturn(false);

		filter.doFilter(request, response, chain);

		verify(response).sendRedirect(startsWith("/Marti/mfa/verify.html"));
		verify(chain, never()).doFilter(request, response);
	}

	@Test
	public void lookupFailureFailsClosed() throws Exception {
		when(mfaService.isTokenVerified("tok-1", "alice")).thenThrow(new RuntimeException("db down"));

		filter.doFilter(request, response, chain);

		verify(response).sendRedirect(startsWith("/Marti/mfa/verify.html"));
		verify(chain, never()).doFilter(request, response);
	}

	@Test
	public void noTokenMeansNoLookup() throws Exception {
		when(request.getCookies()).thenReturn(null);

		filter.doFilter(request, response, chain);

		verify(mfaService, never()).isTokenVerified(anyString(), anyString());
		verify(response).sendRedirect(startsWith("/Marti/mfa/verify.html"));
	}

	@Test
	public void apiCallOnPasswordPortWithoutMfaIsRefused() throws Exception {
		when(request.getRequestURI()).thenReturn("/Marti/api/onboarding/users");
		when(request.getHeader("Accept")).thenReturn("application/json");
		when(request.getLocalPort()).thenReturn(8446);
		StringWriter body = new StringWriter();
		when(response.getWriter()).thenReturn(new PrintWriter(body));

		filter.doFilter(request, response, chain);

		verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		verify(chain, never()).doFilter(request, response);
		verify(response, never()).sendRedirect(anyString());
		assertTrue(body.toString().contains("mfa_required"));
	}

	@Test
	public void xhrOnPasswordPortWithoutMfaIsRefused() throws Exception {
		when(request.getRequestURI()).thenReturn("/Marti/api/missions");
		when(request.getHeader("X-Requested-With")).thenReturn("XMLHttpRequest");
		when(request.getLocalPort()).thenReturn(8446);
		when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

		filter.doFilter(request, response, chain);

		verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		verify(chain, never()).doFilter(request, response);
	}

	@Test
	public void apiCallOnCertPortStillPasses() throws Exception {
		// devices call the APIs on 8443 with their certificate; that is their second factor
		when(request.getRequestURI()).thenReturn("/Marti/api/missions");
		when(request.getHeader("Accept")).thenReturn("application/json");
		when(request.getLocalPort()).thenReturn(8443);

		filter.doFilter(request, response, chain);

		verify(chain).doFilter(request, response);
	}

	@Test
	public void apiCallWithMfaPasses() throws Exception {
		when(request.getRequestURI()).thenReturn("/Marti/api/onboarding/users");
		when(request.getHeader("Accept")).thenReturn("application/json");
		when(request.getLocalPort()).thenReturn(8446);
		when(mfaService.isTokenVerified("tok-1", "alice")).thenReturn(true);

		filter.doFilter(request, response, chain);

		verify(chain).doFilter(request, response);
	}

	@Test
	public void landingPageLookupNeedsNoMfa() throws Exception {
		when(request.getRequestURI()).thenReturn("/Marti/api/home");
		when(request.getHeader("Accept")).thenReturn("*/*");
		when(request.getLocalPort()).thenReturn(8446);

		filter.doFilter(request, response, chain);

		verify(chain).doFilter(request, response);
	}
}
