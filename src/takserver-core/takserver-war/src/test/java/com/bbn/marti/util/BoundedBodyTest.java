package com.bbn.marti.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.Test;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;

public class BoundedBodyTest {

	private static final int CAP = 1024;

	/** ServletInputStream over a byte array that records how many bytes were consumed. */
	private static class CountingInputStream extends ServletInputStream {
		private final ByteArrayInputStream in;
		int consumed;

		CountingInputStream(byte[] data) {
			in = new ByteArrayInputStream(data);
		}

		@Override
		public int read() {
			int b = in.read();
			if (b != -1) {
				consumed++;
			}
			return b;
		}

		@Override
		public int read(byte[] b, int off, int len) {
			int n = in.read(b, off, len);
			if (n > 0) {
				consumed += n;
			}
			return n;
		}

		@Override
		public boolean isFinished() {
			return in.available() == 0;
		}

		@Override
		public boolean isReady() {
			return true;
		}

		@Override
		public void setReadListener(ReadListener readListener) {
		}
	}

	private static byte[] bytes(int n) {
		byte[] b = new byte[n];
		Arrays.fill(b, (byte) 'a');
		return b;
	}

	private static HttpServletRequest request(CountingInputStream body, long contentLength, String contentType) throws IOException {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getContentLengthLong()).thenReturn(contentLength);
		when(request.getContentType()).thenReturn(contentType);
		when(request.getMethod()).thenReturn("PUT");
		when(request.getInputStream()).thenReturn(body);
		return request;
	}

	@Test
	public void underCapIsReturned() throws IOException {
		byte[] data = bytes(CAP - 1);
		assertArrayEquals(data, BoundedBody.read(request(new CountingInputStream(data), data.length, null), CAP));
	}

	@Test
	public void exactlyCapIsReturned() throws IOException {
		byte[] data = bytes(CAP);
		assertArrayEquals(data, BoundedBody.read(request(new CountingInputStream(data), data.length, null), CAP));
	}

	@Test
	public void emptyBodyIsEmptyArray() throws IOException {
		assertEquals(0, BoundedBody.read(request(new CountingInputStream(new byte[0]), 0, null), CAP).length);
	}

	@Test
	public void overCapWithContentLengthIsRejectedWithoutReading() throws IOException {
		CountingInputStream body = new CountingInputStream(bytes(CAP + 1));
		HttpServletRequest request = request(body, CAP + 1, null);
		try {
			BoundedBody.read(request, CAP);
			fail("expected PayloadTooLargeException");
		} catch (PayloadTooLargeException e) {
			assertEquals(CAP, e.getLimit());
		}
		verify(request, never()).getInputStream();
		assertEquals(0, body.consumed);
	}

	@Test
	public void overCapChunkedIsRejectedAfterCapPlusOneBytes() throws IOException {
		// no Content-Length (chunked): the limit must still hold while reading
		CountingInputStream body = new CountingInputStream(bytes(CAP * 50));
		try {
			BoundedBody.read(request(body, -1, null), CAP);
			fail("expected PayloadTooLargeException");
		} catch (PayloadTooLargeException e) {
			assertEquals(CAP, e.getLimit());
		}
		assertTrue("read " + body.consumed + " bytes", body.consumed <= CAP + 1);
	}

	@Test
	public void declaredLengthOverCapIsRejected() throws IOException {
		// a lying small body with a huge declared length (e.g. over 2 GB) is refused up front
		CountingInputStream body = new CountingInputStream(bytes(10));
		try {
			BoundedBody.read(request(body, 5L * 1024 * 1024 * 1024, null), CAP);
			fail("expected PayloadTooLargeException");
		} catch (PayloadTooLargeException expected) {
		}
		assertEquals(0, body.consumed);
	}

	@Test
	public void understatedContentLengthStillCapped() throws IOException {
		// declared length under the cap, but more data actually arrives
		CountingInputStream body = new CountingInputStream(bytes(CAP * 4));
		try {
			BoundedBody.read(request(body, 10, null), CAP);
			fail("expected PayloadTooLargeException");
		} catch (PayloadTooLargeException expected) {
		}
		assertTrue(body.consumed <= CAP + 1);
	}

	@Test
	public void streamVariantChecksDeclaredLengthAndData() throws IOException {
		byte[] data = bytes(CAP);
		assertArrayEquals(data, BoundedBody.read(new CountingInputStream(data), -1, CAP));
		try {
			BoundedBody.read(new CountingInputStream(bytes(CAP + 1)), -1, CAP);
			fail("expected PayloadTooLargeException");
		} catch (PayloadTooLargeException expected) {
		}
		try {
			BoundedBody.read(new CountingInputStream(bytes(1)), CAP + 1, CAP);
			fail("expected PayloadTooLargeException");
		} catch (PayloadTooLargeException expected) {
		}
	}

	@Test
	public void readStringUsesContentTypeCharset() throws IOException {
		byte[] utf8 = "héllo".getBytes(StandardCharsets.UTF_8);
		assertEquals("héllo", BoundedBody.readString(
				request(new CountingInputStream(utf8), utf8.length, "text/plain;charset=UTF-8"), CAP));
		assertEquals("héllo", BoundedBody.readString(
				request(new CountingInputStream(utf8), utf8.length, "application/json"), CAP));
		// no charset: ISO-8859-1, as Spring's String converter does
		assertEquals(new String(utf8, StandardCharsets.ISO_8859_1), BoundedBody.readString(
				request(new CountingInputStream(utf8), utf8.length, "text/plain"), CAP));
		assertEquals(StandardCharsets.ISO_8859_1, BoundedBody.charsetOf("not a media type"));
	}
}
