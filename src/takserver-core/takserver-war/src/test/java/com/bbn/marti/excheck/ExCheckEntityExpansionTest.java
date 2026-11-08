package com.bbn.marti.excheck;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import com.bbn.marti.excheck.checklist.Checklist;
import com.bbn.marti.excheck.checklist.ChecklistTask;

/**
 * GET /Marti/api/excheck/template/{uid} (any cert holder) unmarshals whatever
 * enterprise sync content has that UID, and /Marti/sync/upload lets any cert
 * holder store content under a UID of their choosing. Secure processing only
 * caps Xerces at 100k entity expansions, so one 50k-char entity referenced 50k
 * times (~200 KB body) still unmarshals to 2.5e9 chars and exhausts the heap
 * (CWE-776). Checklists never carry a DOCTYPE, so it is refused.
 */
public class ExCheckEntityExpansionTest {

	private static String quadraticBlowup(String root, String inner) {
		StringBuilder sb = new StringBuilder("<?xml version=\"1.0\"?><!DOCTYPE " + root + " [<!ENTITY a \"");
		for (int i = 0; i < 50_000; i++) {
			sb.append('A');
		}
		sb.append("\">]><" + root + "><" + inner + ">");
		for (int i = 0; i < 50_000; i++) {
			sb.append("&a;");
		}
		sb.append("</" + inner + "></" + root + ">");
		return sb.toString();
	}

	private static String externalEntity(String root, String inner) {
		return "<?xml version=\"1.0\"?><!DOCTYPE " + root + " [<!ENTITY x SYSTEM \"file:///etc/hosts\">]><"
				+ root + "><" + inner + ">&x;</" + inner + "></" + root + ">";
	}

	@Test(timeout = 10_000)
	public void checklistEntityExpansionIsRejected() {
		assertNull(new ExCheckService().checklistFromXml(quadraticBlowup("checklist", "checklistDetails")));
	}

	@Test(timeout = 10_000)
	public void checklistTaskEntityExpansionIsRejected() {
		assertNull(new ExCheckService().checklistTaskFromXml(quadraticBlowup("checklistTask", "value")));
	}

	@Test
	public void externalEntityIsRejected() {
		assertNull(new ExCheckService().checklistFromXml(externalEntity("checklist", "checklistDetails")));
		assertNull(new ExCheckService().checklistTaskFromXml(externalEntity("checklistTask", "value")));
	}

	@Test
	public void plainChecklistStillParses() {
		Checklist checklist = new ExCheckService().checklistFromXml(
				"<?xml version=\"1.0\"?><checklist><checklistDetails><name>pre-flight</name><uid>abc</uid></checklistDetails></checklist>");
		assertNotNull(checklist);
		assertEquals("pre-flight", checklist.getChecklistDetails().getName());

		ChecklistTask task = new ExCheckService().checklistTaskFromXml(
				"<?xml version=\"1.0\"?><checklistTask><uid>t1</uid><value>check fuel</value></checklistTask>");
		assertNotNull(task);
		assertEquals("t1", task.getUid());
	}
}
