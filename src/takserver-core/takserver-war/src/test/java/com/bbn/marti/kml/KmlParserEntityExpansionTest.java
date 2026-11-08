package com.bbn.marti.kml;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import de.micromata.opengis.kml.v_2_2_0.Document;
import de.micromata.opengis.kml.v_2_2_0.Kml;

/**
 * /Marti/TracksKML POST (any authenticated user) feeds the body to KmlParser.
 * takserver.war bundles xercesImpl, which has no entity expansion limit by
 * default: a ~700 byte "billion laughs" body expanded to 3e10 chars before
 * secure processing / disallow-doctype-decl were enabled (CWE-776).
 */
public class KmlParserEntityExpansionTest {

	private static String billionLaughs() {
		StringBuilder sb = new StringBuilder("<?xml version=\"1.0\"?><!DOCTYPE kml [<!ENTITY l0 \"lollollollollollollollollollol\">");
		for (int i = 1; i <= 9; i++) {
			sb.append("<!ENTITY l").append(i).append(" \"");
			for (int j = 0; j < 10; j++) {
				sb.append("&l").append(i - 1).append(';');
			}
			sb.append("\">");
		}
		sb.append("]><kml xmlns=\"http://www.opengis.net/kml/2.2\"><Document><name>&l9;</name></Document></kml>");
		return sb.toString();
	}

	@Test(timeout = 10_000)
	public void entityExpansionIsRejected() {
		assertNull(KmlParser.unmarshal(billionLaughs()));
	}

	@Test
	public void plainKmlStillParses() {
		Kml kml = KmlParser.unmarshal("<?xml version=\"1.0\"?><kml xmlns=\"http://www.opengis.net/kml/2.2\"><Document><name>tracks</name></Document></kml>");
		assertNotNull(kml);
		assertNotNull(((Document) kml.getFeature()).getName());
	}
}
