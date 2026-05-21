package com.bbn.marti.maplayer;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.bbn.marti.maplayer.api.MapLayersApi;

/**
 * Bounds the /maplayers/all response truncation. GET is ROLE_ANONYMOUS in
 * security-context.xml; without a cap any authenticated caller can force
 * the server to serialize every map layer in the DB per request (CWE-400,
 * CWE-770).
 */
public class MapLayersApiCapTest {

	@Test
	public void zeroIsAccepted() {
		assertFalse(MapLayersApi.shouldTruncateMapLayers(0, 1000));
	}

	@Test
	public void atCapAccepted() {
		assertFalse(MapLayersApi.shouldTruncateMapLayers(1000, 1000));
	}

	@Test
	public void oneOverTruncated() {
		assertTrue(MapLayersApi.shouldTruncateMapLayers(1001, 1000));
	}

	@Test
	public void floodTruncated() {
		assertTrue(MapLayersApi.shouldTruncateMapLayers(1_000_000, 1000));
	}

	@Test
	public void defaultCapIsReasonable() {
		assertTrue(MapLayersApi.MAX_MAP_LAYERS_PER_RESPONSE >= 100);
		assertTrue(MapLayersApi.MAX_MAP_LAYERS_PER_RESPONSE <= 100_000);
	}
}
