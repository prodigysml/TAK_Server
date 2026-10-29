package tak.server;

import static org.junit.Assert.assertEquals;

import java.util.concurrent.atomic.AtomicReference;

import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.RemoteIpValve;
import org.apache.catalina.valves.ValveBase;
import org.junit.Test;

/**
 * The client address comes from X-Forwarded-For only when the connection is
 * from loopback (the local reverse proxy). A remote client can't set its own
 * address with the header, and the scheme and port are left alone.
 */
public class RemoteIpValveConfigTest {

	private static String[] run(String remoteAddr, String xff) throws Exception {
		RemoteIpValve valve = CustomizeEmbeddedTomcatContainer.remoteIpValve();
		AtomicReference<String[]> seen = new AtomicReference<>();
		valve.setNext(new ValveBase() {
			@Override
			public void invoke(Request request, Response response) {
				seen.set(new String[] { request.getRemoteAddr(), request.getScheme(), String.valueOf(request.getServerPort()) });
			}
		});

		Request request = new Request(new Connector());
		request.setCoyoteRequest(new org.apache.coyote.Request());
		request.setRemoteAddr(remoteAddr);
		request.setRemoteHost(remoteAddr);
		request.getCoyoteRequest().scheme().setString("https");
		request.getCoyoteRequest().setServerPort(8446);
		if (xff != null) {
			request.getCoyoteRequest().getMimeHeaders().addValue("X-Forwarded-For").setString(xff);
			request.getCoyoteRequest().getMimeHeaders().addValue("X-Forwarded-Proto").setString("http");
		}
		valve.invoke(request, null);
		return seen.get();
	}

	@Test
	public void loopbackProxyHeaderIsUsed() throws Exception {
		assertEquals("203.0.113.7", run("127.0.0.1", "203.0.113.7")[0]);
	}

	@Test
	public void remoteClientHeaderIsIgnored() throws Exception {
		assertEquals("198.51.100.9", run("198.51.100.9", "203.0.113.7")[0]);
	}

	@Test
	public void spoofedHopBeforeTheRealClientIsIgnored() throws Exception {
		// nginx appends the address it saw to whatever the client sent
		assertEquals("203.0.113.7", run("127.0.0.1", "1.2.3.4, 203.0.113.7")[0]);
	}

	@Test
	public void schemeAndPortUnchanged() throws Exception {
		String[] seen = run("127.0.0.1", "203.0.113.7");
		assertEquals("https", seen[1]);
		assertEquals("8446", seen[2]);
	}

	@Test
	public void noHeaderKeepsTheConnectionAddress() throws Exception {
		assertEquals("127.0.0.1", run("127.0.0.1", null)[0]);
	}
}
