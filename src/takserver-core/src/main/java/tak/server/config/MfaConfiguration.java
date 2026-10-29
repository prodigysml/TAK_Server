package tak.server.config;

import java.util.Locale;

import javax.sql.DataSource;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.bbn.marti.config.Network;
import com.bbn.marti.mfa.LoginAttemptService;
import com.bbn.marti.mfa.MfaGateFilter;
import com.bbn.marti.mfa.MfaService;
import com.bbn.marti.remote.config.CoreConfigFacade;
import com.bbn.marti.revocation.RevocationAuditService;

/**
 * Beans referenced by security-context.xml must be resolvable by every
 * profile that loads ServerConfiguration — messaging, config, and api all
 * import the same security-context.xml via @ImportResource. Pulling the
 * MFA filter and its service out of ApiConfiguration (which is
 * @Profile("api","monolith")) lets the non-api JVMs satisfy the bean
 * reference without crashing during context init.
 *
 * The messaging and config JVMs never serve HTTP requests, so the filter
 * is wired but never fires there. The service's DataSource is lazy via
 * ObjectProvider, so no Postgres connection is opened until something
 * actually calls findByUsername/getOrProvision (api-only).
 */
@Configuration
public class MfaConfiguration {

	@Bean
	public MfaService mfaService(ObjectProvider<DataSource> dataSourceProvider) {
		return new MfaService(dataSourceProvider);
	}

	/**
	 * Shares MfaConfiguration rather than living in ApiConfiguration for the same
	 * reason the MFA beans do: it must resolve under every profile that loads
	 * ServerConfiguration. Its DataSource is lazy, so the messaging and config
	 * JVMs wire it without ever opening a connection.
	 */
	@Bean
	public RevocationAuditService revocationAuditService(ObjectProvider<DataSource> dataSourceProvider) {
		return new RevocationAuditService(dataSourceProvider);
	}

	@Bean
	public LoginAttemptService loginAttemptService() {
		return new LoginAttemptService();
	}

	@Bean(name = "mfaGateFilter")
	public MfaGateFilter mfaGateFilter(MfaService mfaService) {
		return new MfaGateFilter(mfaService, MfaConfiguration::certRequiredPort);
	}

	/**
	 * True when the connector on this local port makes Tomcat require a client
	 * certificate (CoreConfig clientAuth="true", the default). An unknown port
	 * counts as not requiring one, so MFA is enforced there.
	 */
	static boolean certRequiredPort(int port) {
		try {
			for (Network.Connector c : CoreConfigFacade.getInstance().getRemoteConfiguration().getNetwork().getConnector()) {
				if (c.getPort() == port) {
					String auth = c.getClientAuth() == null ? "" : c.getClientAuth().toLowerCase(Locale.ENGLISH);
					return c.isTls() && (auth.equals("true") || auth.equals("required"));
				}
			}
		} catch (RuntimeException e) {
			// fall through: enforce MFA
		}
		return false;
	}

	/**
	 * Prevent Spring Boot auto-registration of MfaGateFilter with the servlet
	 * container. The filter is invoked from inside Spring Security's chain
	 * via security-context.xml &lt;sec:filter-chain ... filters="...,mfaGateFilter"&gt;.
	 * Without this, BootServletInitializer would also register the filter
	 * directly on Tomcat, blocking startup on bean init order.
	 */
	@Bean
	public FilterRegistrationBean<MfaGateFilter> mfaGateFilterRegistration(MfaGateFilter mfaGateFilter) {
		FilterRegistrationBean<MfaGateFilter> reg = new FilterRegistrationBean<>(mfaGateFilter);
		reg.setEnabled(false);
		return reg;
	}
}
