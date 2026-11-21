package com.bbn.marti.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpRequest;

import com.google.common.io.ByteStreams;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Reads a raw (non-multipart) request body with a hard size cap. The servlet multipart limit
 * does not apply to raw bodies, so reading the whole body and checking its length afterwards
 * lets a client exhaust heap with one huge (or chunked, length-less) request. This checks the
 * declared Content-Length first and then never buffers more than cap + 1 bytes.
 */
public final class BoundedBody {

	private BoundedBody() {
	}

	/**
	 * Reads the request body the same way Spring's {@code @RequestBody byte[]} does (including
	 * form-encoded POST bodies), but stops once more than {@code maxBytes} bytes arrive.
	 *
	 * @throws PayloadTooLargeException if the body is larger than {@code maxBytes}
	 */
	public static byte[] read(HttpServletRequest request, long maxBytes) throws IOException {
		if (request.getContentLengthLong() > maxBytes) {
			throw new PayloadTooLargeException(maxBytes);
		}
		return read(new ServletServerHttpRequest(request).getBody(), -1, maxBytes);
	}

	/**
	 * Reads at most {@code maxBytes} bytes from {@code in}.
	 *
	 * @param declaredLength the declared body length, or -1 if unknown (chunked)
	 * @throws PayloadTooLargeException if the declared length or the actual data exceeds {@code maxBytes}
	 */
	public static byte[] read(InputStream in, long declaredLength, long maxBytes) throws IOException {
		if (declaredLength > maxBytes) {
			throw new PayloadTooLargeException(maxBytes);
		}
		if (in == null) {
			return new byte[0];
		}
		byte[] body = IOUtils.toByteArray(ByteStreams.limit(in, maxBytes + 1));
		if (body.length > maxBytes) {
			throw new PayloadTooLargeException(maxBytes);
		}
		return body;
	}

	/**
	 * Like {@link #read(HttpServletRequest, long)}, decoded the way Spring's
	 * {@code @RequestBody String} does: the Content-Type charset if given, UTF-8 for JSON,
	 * otherwise ISO-8859-1.
	 */
	public static String readString(HttpServletRequest request, long maxBytes) throws IOException {
		return new String(read(request, maxBytes), charsetOf(request.getContentType()));
	}

	static Charset charsetOf(String contentType) {
		if (contentType != null) {
			try {
				MediaType mediaType = MediaType.parseMediaType(contentType);
				if (mediaType.getCharset() != null) {
					return mediaType.getCharset();
				}
				if (mediaType.isCompatibleWith(MediaType.APPLICATION_JSON)) {
					return StandardCharsets.UTF_8;
				}
			} catch (RuntimeException e) {
				// unparseable content type or unknown charset: fall through to the default
			}
		}
		return StandardCharsets.ISO_8859_1;
	}
}
