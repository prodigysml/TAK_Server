package com.bbn.marti.network;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

/**
 * The data package hands certPass to the device to open its .p12, so the
 * server has to reject a password that does not open it.
 */
public class OnboardingCertPassTest {

	private static byte[] p12(String pass) throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(null, null);
		ks.setEntry("user", new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[16], "AES")),
				new KeyStore.PasswordProtection(pass.toCharArray()));
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ks.store(out, pass.toCharArray());
		return out.toByteArray();
	}

	@Test
	public void rightPasswordOpensTheCert() throws Exception {
		assertTrue(OnboardingApi.certPassOpens(p12("right-pass"), "right-pass"));
	}

	@Test
	public void wrongPasswordIsRefused() throws Exception {
		assertFalse(OnboardingApi.certPassOpens(p12("right-pass"), "wrong-pass"));
	}

	@Test(expected = IllegalStateException.class)
	public void damagedCertIsNotAPasswordMistake() {
		OnboardingApi.certPassOpens(new byte[] { 1, 2, 3 }, "right-pass");
	}
}
