package com.bbn.marti.mfa;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pure Java TOTP (RFC 6238) helper for the admin MFA gate.
 *
 * Deliberately self-contained — no third-party TOTP lib added to the build:
 *   - {@link #generateSecret()} produces a 20-byte random secret, base32-encoded
 *     for compatibility with Google Authenticator / Authy / 1Password.
 *   - {@link #generateCode(String, long)} returns the 6-digit code for a given
 *     base32 secret and time bucket.
 *   - {@link #verify(String, String)} accepts a one-step window on either side
 *     (±30 seconds) to absorb clock skew between server and phone.
 *   - {@link #otpAuthUri(String, String, String)} builds the otpauth:// URI
 *     consumed by QR-code generators.
 *
 * Constants follow RFC 6238 defaults: SHA1, 30-second step, 6 digits. Google
 * Authenticator does not honour non-default values for the alg/digits fields
 * in the otpauth URI, so changing them would silently break the apps.
 */
public final class TotpUtil {

	private static final int STEP_SECONDS = 30;
	private static final int DIGITS = 6;
	private static final int SECRET_BYTES = 20; // 160 bits, RFC 4226 minimum
	private static final SecureRandom RANDOM = new SecureRandom();
	private static final Pattern BASE32 = Pattern.compile("^[A-Z2-7]+=*$");

	private TotpUtil() {}

	public static String generateSecret() {
		byte[] raw = new byte[SECRET_BYTES];
		RANDOM.nextBytes(raw);
		return base32Encode(raw);
	}

	public static String otpAuthUri(String issuer, String account, String secretB32) {
		String enc = urlEncode(issuer) + ":" + urlEncode(account);
		return "otpauth://totp/" + enc
				+ "?secret=" + secretB32
				+ "&issuer=" + urlEncode(issuer)
				+ "&algorithm=SHA1&digits=" + DIGITS + "&period=" + STEP_SECONDS;
	}

	public static String generateCode(String secretB32, long unixSeconds) {
		long bucket = unixSeconds / STEP_SECONDS;
		byte[] secret = base32Decode(secretB32);
		byte[] data = ByteBuffer.allocate(8).putLong(bucket).array();
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(new SecretKeySpec(secret, "HmacSHA1"));
			byte[] hash = mac.doFinal(data);
			int off = hash[hash.length - 1] & 0x0f;
			int code = ((hash[off] & 0x7f) << 24)
					| ((hash[off + 1] & 0xff) << 16)
					| ((hash[off + 2] & 0xff) << 8)
					| (hash[off + 3] & 0xff);
			int mod = (int) Math.pow(10, DIGITS);
			return String.format("%0" + DIGITS + "d", code % mod);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new IllegalStateException("HmacSHA1 missing from JCE", e);
		}
	}

	/**
	 * Verify a user-supplied 6-digit code against the secret. Accepts the
	 * code for the current 30-second bucket plus the immediately prior and
	 * next bucket to absorb phone/server clock skew.
	 */
	public static boolean verify(String secretB32, String userCode) {
		if (userCode == null || !userCode.matches("\\d{" + DIGITS + "}")) {
			return false;
		}
		if (secretB32 == null || !BASE32.matcher(secretB32).matches()) {
			return false;
		}
		long now = System.currentTimeMillis() / 1000L;
		for (int step = -1; step <= 1; step++) {
			String expected = generateCode(secretB32, now + (long) step * STEP_SECONDS);
			// Constant-time equality — bcrypt-style timing-safe compare.
			if (constantTimeEquals(expected, userCode)) {
				return true;
			}
		}
		return false;
	}

	private static boolean constantTimeEquals(String a, String b) {
		if (a == null || b == null || a.length() != b.length()) return false;
		int diff = 0;
		for (int i = 0; i < a.length(); i++) {
			diff |= a.charAt(i) ^ b.charAt(i);
		}
		return diff == 0;
	}

	private static final char[] BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

	static String base32Encode(byte[] data) {
		StringBuilder sb = new StringBuilder();
		int buffer = 0, bitsLeft = 0;
		for (byte b : data) {
			buffer = (buffer << 8) | (b & 0xff);
			bitsLeft += 8;
			while (bitsLeft >= 5) {
				bitsLeft -= 5;
				sb.append(BASE32_ALPHABET[(buffer >> bitsLeft) & 0x1f]);
			}
		}
		if (bitsLeft > 0) {
			sb.append(BASE32_ALPHABET[(buffer << (5 - bitsLeft)) & 0x1f]);
		}
		return sb.toString();
	}

	static byte[] base32Decode(String s) {
		String clean = s.replace("=", "").toUpperCase().replace(" ", "");
		byte[] out = new byte[clean.length() * 5 / 8];
		int buffer = 0, bitsLeft = 0, idx = 0;
		for (char c : clean.toCharArray()) {
			int val;
			if (c >= 'A' && c <= 'Z') val = c - 'A';
			else if (c >= '2' && c <= '7') val = c - '2' + 26;
			else throw new IllegalArgumentException("Bad base32 char: " + c);
			buffer = (buffer << 5) | val;
			bitsLeft += 5;
			if (bitsLeft >= 8) {
				bitsLeft -= 8;
				out[idx++] = (byte) ((buffer >> bitsLeft) & 0xff);
			}
		}
		return out;
	}

	private static String urlEncode(String s) {
		try {
			return java.net.URLEncoder.encode(s, "UTF-8")
					.replace("+", "%20");
		} catch (java.io.UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}
}
