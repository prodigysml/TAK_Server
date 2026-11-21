package com.bbn.tak.tls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The certificate admin API returns TakCert objects as JSON. The enrollment token on a
 * TakCert is a live bearer credential, so it must never be serialized; the response only
 * says whether one exists.
 */
public class TakCertJsonTest {

	// Avoids building a real X509Certificate: only the PEM and serial getters need one.
	static class NoPemCert extends TakCert {
		private static final long serialVersionUID = 1L;

		@Override
		public String getCertificate() {
			return "PEM";
		}

		@Override
		public String getSerialNumber() {
			return "01";
		}
	}

	private static JsonNode toJson(TakCert cert) throws Exception {
		return new ObjectMapper().readTree(new ObjectMapper().writeValueAsString(cert));
	}

	@Test
	public void tokenIsNotSerialized() throws Exception {
		NoPemCert cert = new NoPemCert();
		cert.setSubjectDn("CN=alice");
		cert.setToken("eyJhbGciOiJSUzI1NiJ9.secret.sig");

		JsonNode json = toJson(cert);

		assertFalse(json.has("token"));
		assertFalse(json.toString().contains("secret"));
		assertEquals(true, json.get("hasToken").asBoolean());
		assertEquals("CN=alice", json.get("subjectDn").asText());
	}

	@Test
	public void hasTokenFalseWithoutToken() throws Exception {
		NoPemCert cert = new NoPemCert();
		assertEquals(false, toJson(cert).get("hasToken").asBoolean());

		cert.setToken("");
		assertEquals(false, toJson(cert).get("hasToken").asBoolean());
	}

	@Test
	public void tokenStillReadableInJava() {
		TakCert cert = new TakCert();
		cert.setToken("t");
		assertEquals("t", cert.getToken());
		assertEquals("t", cert.token);
	}
}
