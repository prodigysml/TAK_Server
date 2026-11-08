package com.bbn.marti.injector;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.dom4j.DocumentException;
import org.junit.Test;

import com.bbn.marti.config.UidInject;
import com.bbn.marti.remote.exception.TakException;

/**
 * Injector snippets (POST /Marti/api/injectors/cot/uid, CoreConfig) were parsed
 * with DocumentHelper.parseText, an unhardened Xerces reader: a ~600 byte
 * "billion laughs" toInject ran the messaging process out of heap (CWE-776).
 */
public class UidCotTagInjectorEntityExpansionTest {

	// what padToInject turns into "<" + toInject + "/>"
	private static String billionLaughsSnippet() {
		StringBuilder sb = new StringBuilder("!DOCTYPE a [<!ENTITY l0 \"lollollollollollollollollollol\">");
		for (int i = 1; i <= 9; i++) {
			sb.append("<!ENTITY l").append(i).append(" \"");
			for (int j = 0; j < 10; j++) {
				sb.append("&l").append(i - 1).append(';');
			}
			sb.append("\">");
		}
		sb.append("]><a>&l9;</a><b");
		return sb.toString();
	}

	@Test(timeout = 10_000)
	public void entityExpansionInSnippetIsRejected() throws Exception {
		try {
			new UidCotTagInjector().getElementToInject(billionLaughsSnippet());
			fail("DOCTYPE in injector snippet should be refused");
		} catch (TakException expected) {
		}
	}

	@Test(timeout = 10_000)
	public void entityExpansionInAddInjectorIsRejected() throws Exception {
		UidInject inject = new UidInject();
		inject.setUid("u1");
		inject.setToInject("<" + billionLaughsSnippet() + "/>");
		try {
			new UidCotTagInjector().addInjector(inject);
			fail("DOCTYPE in injector should be refused");
		} catch (DocumentException expected) {
		}
	}

	@Test
	public void plainSnippetStillParses() throws Exception {
		assertEquals("<__group name=\"Cyan\" role=\"Team Member\"/>",
				new UidCotTagInjector().getElementToInject("__group name=\"Cyan\" role=\"Team Member\"").asXML());
	}
}
