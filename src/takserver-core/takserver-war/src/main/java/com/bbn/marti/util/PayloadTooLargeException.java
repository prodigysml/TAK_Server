package com.bbn.marti.util;

/**
 * Thrown when a request body (or a stored object about to be loaded) is larger than the
 * limit allowed for that endpoint. Mapped to HTTP 413 by CustomExceptionHandler.
 */
public class PayloadTooLargeException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	private final long limit;

	public PayloadTooLargeException(long limit) {
		super("Payload exceeds maximum allowed size of " + limit + " bytes");
		this.limit = limit;
	}

	public long getLimit() {
		return limit;
	}
}
