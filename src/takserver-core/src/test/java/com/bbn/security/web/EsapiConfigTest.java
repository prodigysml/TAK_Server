package com.bbn.security.web;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.owasp.esapi.ESAPI;

/**
 * ESAPI reads ESAPI.properties and validation.properties the first time it is
 * used, so a bad config or a config file a newer ESAPI no longer accepts only
 * shows up at runtime, as a failure in every page that encodes output. Load
 * TAK's real config here so a version bump that breaks it fails the build.
 */
public class EsapiConfigTest {

	@Test
	public void encoderLoadsWithTakConfig() throws Exception {
		assertEquals("&lt;b&gt;x&lt;&#x2f;b&gt;", ESAPI.encoder().encodeForHTML("<b>x</b>"));
		assertEquals("a+b%26c", ESAPI.encoder().encodeForURL("a b&c"));
	}

	@Test
	public void validatorLoadsWithTakConfig() throws Exception {
		assertEquals("hello", ESAPI.validator().getValidInput("test", "hello", "SafeString", 50, false));
	}
}
