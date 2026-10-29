package com.bbn.marti.sync;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Tests how ContentServlet serves Enterprise Sync files whose type the uploader chose.
 *
 * <p>The stored MIME type used to be sent as-is with Content-Disposition: inline,
 * so a file uploaded as text/html ran as a page in the server's origin when an
 * admin opened it (stored XSS).
 */
public class ContentServletContentTypeTest {

	@Test
	public void activeTypesAreServedAsBytes() {
		for (String t : new String[] { "text/html", "TEXT/HTML; charset=utf-8", " text/html ", "application/xhtml+xml",
				"image/svg+xml", "text/xml", "application/xml", "application/javascript", "text/javascript" }) {
			assertEquals(t, "application/octet-stream", ContentServlet.servedContentType(t));
		}
	}

	@Test
	public void otherTypesAreKept() {
		assertEquals("application/zip", ContentServlet.servedContentType("application/zip"));
		assertEquals("image/png", ContentServlet.servedContentType("image/png"));
		assertEquals("application/vnd.google-earth.kml+xml",
				ContentServlet.servedContentType("application/vnd.google-earth.kml+xml"));
	}

	@Test
	public void onlyPassiveTypesAreShownInline() {
		assertTrue(ContentServlet.isInlineSafe("image/jpeg"));
		assertTrue(ContentServlet.isInlineSafe("application/pdf"));
		assertTrue(ContentServlet.isInlineSafe("Text/Plain; charset=utf-8"));
		assertFalse(ContentServlet.isInlineSafe("text/html"));
		assertFalse(ContentServlet.isInlineSafe("image/svg+xml"));
		assertFalse(ContentServlet.isInlineSafe("application/zip"));
		assertFalse(ContentServlet.isInlineSafe(null));
	}
}
