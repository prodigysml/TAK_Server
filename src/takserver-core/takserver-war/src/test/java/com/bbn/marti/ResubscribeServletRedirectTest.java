package com.bbn.marti;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * ResubscribeServlet redirects back to the page that posted to it. The target
 * comes from the client-controlled Referer header, so only its path and query
 * are used; it used to redirect to any URL (open redirect).
 */
public class ResubscribeServletRedirectTest {

	@Test
	public void keepsPathAndQueryOfOwnPage() {
		assertEquals("/Marti/SubMgr.jsp?x=1", ResubscribeServlet.sameOriginTarget("https://tak.example:8443/Marti/SubMgr.jsp?x=1"));
		assertEquals("/Marti/SubMgr.jsp", ResubscribeServlet.sameOriginTarget("/Marti/SubMgr.jsp"));
	}

	@Test
	public void dropsOtherHosts() {
		assertEquals("/phish", ResubscribeServlet.sameOriginTarget("https://evil.example/phish"));
		// the host of a protocol-relative URL is dropped too
		assertEquals("/x", ResubscribeServlet.sameOriginTarget("//evil.example/x"));
	}

	@Test
	public void refusesJunk() {
		assertEquals(ResubscribeServlet.DEFAULT_REDIRECT, ResubscribeServlet.sameOriginTarget("https://evil.example"));
		assertEquals(ResubscribeServlet.DEFAULT_REDIRECT, ResubscribeServlet.sameOriginTarget("/\\evil.example"));
		assertEquals(ResubscribeServlet.DEFAULT_REDIRECT, ResubscribeServlet.sameOriginTarget("javascript:alert(1)"));
		assertEquals(ResubscribeServlet.DEFAULT_REDIRECT, ResubscribeServlet.sameOriginTarget("not a uri"));
		assertEquals(ResubscribeServlet.DEFAULT_REDIRECT, ResubscribeServlet.sameOriginTarget(null));
	}
}
