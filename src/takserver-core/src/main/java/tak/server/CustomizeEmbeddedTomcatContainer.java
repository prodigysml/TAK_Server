package tak.server;

import java.io.CharArrayWriter;

import org.apache.catalina.valves.AbstractAccessLogValve;
import org.apache.catalina.valves.RemoteIpValve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

import com.bbn.marti.config.Logging;
import com.bbn.marti.remote.config.CoreConfigFacade;

@Component
public class CustomizeEmbeddedTomcatContainer implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

	private static final Logger httpAccessLogger = LoggerFactory.getLogger("http_access_logger");
	private static final Logger logger = LoggerFactory.getLogger(CustomizeEmbeddedTomcatContainer.class);

	@Override
	public void customize(TomcatServletWebServerFactory factory) {

		// Engine valve, so it runs before the access log and authentication.
		factory.addEngineValves(remoteIpValve());

		Logging loggingConf = CoreConfigFacade.getInstance().getRemoteConfiguration().getLogging();

		if (loggingConf != null) {
			logger.info("http access logging enabled: " + loggingConf.isHttpAccessEnabled());
		}


		if (loggingConf != null && loggingConf.isHttpAccessEnabled()) {

			factory.addContextValves(accessLogValve());
		}
	}

	/**
	 * Requests proxied by a reverse proxy on the same host (an nginx sidecar in
	 * front of 8446, for example) arrive from 127.0.0.1, so logs, MFA audit
	 * entries and rate limits all saw the proxy instead of the client. This valve
	 * takes the client address from X-Forwarded-For, but only when the
	 * connection itself comes from loopback; a remote client's own
	 * X-Forwarded-For is ignored. Scheme, port and host are left as they are
	 * (no protocol or port header), so URLs and redirects don't change.
	 */
	static RemoteIpValve remoteIpValve() {
		RemoteIpValve valve = new RemoteIpValve();
		valve.setInternalProxies("127\\.0\\.0\\.1|0:0:0:0:0:0:0:1|::1");
		valve.setTrustedProxies(null);
		valve.setRemoteIpHeader("X-Forwarded-For");
		valve.setProtocolHeader(null);
		valve.setPortHeader(null);
		valve.setHostHeader(null);
		return valve;
	}

	static TomcatSlf4jAccessValve accessLogValve() {
		TomcatSlf4jAccessValve accessLogValve = new TomcatSlf4jAccessValve();
		accessLogValve.setEnabled(true);
		// The entry is written after the request completes, when RemoteIpValve
		// has already put the proxy's address back; read the client address it
		// saved in the request attributes instead.
		accessLogValve.setRequestAttributesEnabled(true);

		/**
		 * for pattern format see https://tomcat.apache.org/tomcat-7.0-doc/api/org/apache/catalina/valves/AccessLogValve.html
		 */
		accessLogValve.setPattern("request: method=%m uri=\"%U\" response: statuscode=%s bytes=%b duration=%D(ms) client: remoteip=%a user=%u useragent=\"%{User-Agent}i\"");
		return accessLogValve;
	}

	public static class TomcatSlf4jAccessValve extends AbstractAccessLogValve {

		@Override
		protected void log(CharArrayWriter message) {
			httpAccessLogger.info(message.toString());
		}

	}
}