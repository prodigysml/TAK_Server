package com.bbn.tak.tls.WSTEP;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * Bounds the CSR-size cap on WSTEPClient.submitCSR. The CSR string flows
 * through /Marti/api/tls/signClient which is ROLE_NO_CLIENT_CERT
 * (anonymous enrollment); without a cap an attacker could submit an
 * arbitrarily large payload that gets materialized as a SOAP text node
 * and forwarded to the upstream CA (CWE-400).
 */
public class WSTEPClientCsrCapTest {

	@Test
	public void defaultCapIsReasonable() {
		assertTrue(WSTEPClient.MAX_WSTEP_CSR_BYTES >= 4096);
		assertTrue(WSTEPClient.MAX_WSTEP_CSR_BYTES <= 1024 * 1024);
	}

	@Test
	public void oversizeCsrThrowsBeforeNetworkWork() {
		StringBuilder sb = new StringBuilder(WSTEPClient.MAX_WSTEP_CSR_BYTES + 64);
		for (int i = 0; i < WSTEPClient.MAX_WSTEP_CSR_BYTES + 64; i++) {
			sb.append('A');
		}
		try {
			WSTEPClient.submitCSR(sb.toString(), "tpl",
					"https://example/invalid", "u", "p", "ts", "tsp", true, "TLS");
			fail("expected IllegalArgumentException on oversized CSR");
		} catch (IllegalArgumentException expected) {
			assertTrue(expected.getMessage().toLowerCase().contains("csr"));
		} catch (Throwable other) {
			fail("expected IllegalArgumentException, got " + other.getClass().getName()
					+ ": " + other.getMessage());
		}
	}
}
