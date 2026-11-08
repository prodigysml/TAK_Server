package com.bbn.marti.kml.icon.api;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * Icon MIME types come from the iconset zip entry name, so an entry named
 * x.html or x.svg must not be served back as active content (CWE-644).
 */
public class IconsetIconApiMimeTypeTest {

	@Test
	public void rasterTypesPassThrough() {
		assertEquals("image/png", IconsetIconApi.safeIconMimeType("image/png"));
		assertEquals("image/jpeg", IconsetIconApi.safeIconMimeType("image/jpeg"));
		assertEquals("image/gif", IconsetIconApi.safeIconMimeType("IMAGE/GIF"));
	}

	@Test
	public void activeContentFallsBackToPng() {
		assertEquals("image/png", IconsetIconApi.safeIconMimeType("text/html"));
		assertEquals("image/png", IconsetIconApi.safeIconMimeType("image/svg+xml"));
		assertEquals("image/png", IconsetIconApi.safeIconMimeType("application/xhtml+xml"));
		assertEquals("image/png", IconsetIconApi.safeIconMimeType("image/png\r\nX-Injected: 1"));
	}

	@Test
	public void missingFallsBackToPng() {
		assertEquals("image/png", IconsetIconApi.safeIconMimeType(null));
		assertEquals("image/png", IconsetIconApi.safeIconMimeType(""));
	}
}
