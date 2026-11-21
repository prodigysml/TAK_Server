package com.bbn.marti.sync.api;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

/**
 * Response headers for endpoints that return stored CoT as XML.
 *
 * A CoT event's &lt;detail&gt; is free-form XML written by whichever client sent it, and
 * it is returned verbatim. Served as application/xml, a browser will run an
 * XHTML-namespaced &lt;script&gt; inside it on the server's origin, so any client able to
 * send CoT could plant script that runs as whoever opens the link (an admin, with
 * their client certificate). The sandbox CSP stops script and same-origin access in
 * the rendered document, and nosniff stops the browser treating it as anything else.
 * TAK clients don't interpret these headers, so they are unaffected.
 */
final class CotXmlHeaders {

	static final String CONTENT_SECURITY_POLICY = "default-src 'none'; sandbox";

	private CotXmlHeaders() {
	}

	static HttpHeaders apply(HttpHeaders headers) {
		headers.setContentType(MediaType.APPLICATION_XML);
		headers.set("X-Content-Type-Options", "nosniff");
		headers.set("Content-Security-Policy", CONTENT_SECURITY_POLICY);
		return headers;
	}
}
