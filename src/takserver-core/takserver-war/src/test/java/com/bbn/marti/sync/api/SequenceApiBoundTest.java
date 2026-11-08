package com.bbn.marti.sync.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * /Marti/api/sync/sequence/{key} is reachable by any authenticated user and
 * the key is caller-chosen; the backing map must stay bounded (CWE-400).
 */
public class SequenceApiBoundTest {

	@Test
	public void sequenceIncrements() throws Exception {
		SequenceApi api = new SequenceApi();
		assertEquals("1", api.getNextInSequence("seq-bound-test-a").getBody());
		assertEquals("2", api.getNextInSequence("seq-bound-test-a").getBody());
	}

	@Test
	public void distinctKeysDoNotGrowPastCap() throws Exception {
		SequenceApi api = new SequenceApi();
		for (int i = 0; i < SequenceApi.MAX_SEQUENCE_KEYS * 3; i++) {
			api.getNextInSequence("flood-" + i);
		}
		SequenceApi.sequenceCache.cleanUp();
		assertTrue(SequenceApi.sequenceCache.estimatedSize() <= SequenceApi.MAX_SEQUENCE_KEYS);
	}

	@Test(expected = IllegalArgumentException.class)
	public void oversizedKeyRejected() throws Exception {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i <= SequenceApi.MAX_SEQUENCE_KEY_LENGTH; i++) {
			sb.append('k');
		}
		new SequenceApi().getNextInSequence(sb.toString());
	}
}
