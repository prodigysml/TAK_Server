package com.bbn.marti.mfa;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * RFC 6238 conformance tests for {@link TotpUtil}.
 *
 * The 8-digit reference codes in RFC 6238 Appendix B are computed from
 * H(secret, T) mod 10^8 with secret = "12345678901234567890" (ASCII).
 * Our implementation emits 6-digit codes (mod 10^6), so the expected
 * value is the last six characters of each RFC vector. This is the same
 * truncation used by Google Authenticator and friends.
 */
public class TotpUtilTest {

	// Base32 of the 20 ASCII bytes "12345678901234567890"
	private static final String RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

	@Test
	public void rfc6238_vector_59seconds() {
		assertEquals("287082", TotpUtil.generateCode(RFC_SECRET_B32, 59L));
	}

	@Test
	public void rfc6238_vector_1111111109() {
		assertEquals("081804", TotpUtil.generateCode(RFC_SECRET_B32, 1111111109L));
	}

	@Test
	public void rfc6238_vector_1111111111() {
		assertEquals("050471", TotpUtil.generateCode(RFC_SECRET_B32, 1111111111L));
	}

	@Test
	public void rfc6238_vector_1234567890() {
		assertEquals("005924", TotpUtil.generateCode(RFC_SECRET_B32, 1234567890L));
	}

	@Test
	public void rfc6238_vector_2000000000() {
		assertEquals("279037", TotpUtil.generateCode(RFC_SECRET_B32, 2000000000L));
	}

	@Test
	public void verifyAcceptsCurrentBucketCode() {
		long now = System.currentTimeMillis() / 1000L;
		String code = TotpUtil.generateCode(RFC_SECRET_B32, now);
		assertTrue(TotpUtil.verify(RFC_SECRET_B32, code));
	}

	@Test
	public void verifyAcceptsPreviousStepWithinSkew() {
		// Generate code for a bucket 30s in the past, current verify call
		// should still accept it (±1 step window).
		long pastBucket = (System.currentTimeMillis() / 1000L) - 30;
		String code = TotpUtil.generateCode(RFC_SECRET_B32, pastBucket);
		assertTrue(TotpUtil.verify(RFC_SECRET_B32, code));
	}

	@Test
	public void verifyAcceptsNextStepWithinSkew() {
		long futureBucket = (System.currentTimeMillis() / 1000L) + 30;
		String code = TotpUtil.generateCode(RFC_SECRET_B32, futureBucket);
		assertTrue(TotpUtil.verify(RFC_SECRET_B32, code));
	}

	@Test
	public void verifyRejectsCodeOutsideSkewWindow() {
		long farPast = (System.currentTimeMillis() / 1000L) - 600;
		String code = TotpUtil.generateCode(RFC_SECRET_B32, farPast);
		assertFalse(TotpUtil.verify(RFC_SECRET_B32, code));
	}

	@Test
	public void verifyRejectsNullCode() {
		assertFalse(TotpUtil.verify(RFC_SECRET_B32, null));
	}

	@Test
	public void verifyRejectsEmptyCode() {
		assertFalse(TotpUtil.verify(RFC_SECRET_B32, ""));
	}

	@Test
	public void verifyRejectsNonDigitCode() {
		assertFalse(TotpUtil.verify(RFC_SECRET_B32, "abcdef"));
	}

	@Test
	public void verifyRejectsWrongLengthCode() {
		assertFalse(TotpUtil.verify(RFC_SECRET_B32, "12345"));
		assertFalse(TotpUtil.verify(RFC_SECRET_B32, "1234567"));
	}

	@Test
	public void verifyRejectsNullSecret() {
		assertFalse(TotpUtil.verify(null, "123456"));
	}

	@Test
	public void verifyRejectsInvalidBase32() {
		assertFalse(TotpUtil.verify("not-base32!!", "123456"));
	}

	@Test
	public void verifyRejectsWrongCode() {
		assertFalse(TotpUtil.verify(RFC_SECRET_B32, "000000"));
	}

	@Test
	public void generateSecretIsValidBase32() {
		String secret = TotpUtil.generateSecret();
		// 20 bytes -> ceil(20*8/5) = 32 base32 chars (no padding)
		assertEquals(32, secret.length());
		assertTrue("secret must be base32: " + secret,
				secret.matches("^[A-Z2-7]+$"));
	}

	@Test
	public void generateSecretIsUnique() {
		String a = TotpUtil.generateSecret();
		String b = TotpUtil.generateSecret();
		assertFalse("two consecutive secrets collided", a.equals(b));
	}

	@Test
	public void base32RoundTrip() {
		byte[] orig = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
		String enc = TotpUtil.base32Encode(orig);
		byte[] back = TotpUtil.base32Decode(enc);
		assertArrayEquals(orig, back);
	}

	@Test
	public void otpAuthUriContainsRequiredFields() {
		String uri = TotpUtil.otpAuthUri("TAK Server", "alice", RFC_SECRET_B32);
		assertTrue(uri.startsWith("otpauth://totp/"));
		assertTrue(uri.contains("secret=" + RFC_SECRET_B32));
		assertTrue(uri.contains("issuer=TAK%20Server"));
		assertTrue(uri.contains("algorithm=SHA1"));
		assertTrue(uri.contains("digits=6"));
		assertTrue(uri.contains("period=30"));
	}
}
