package tak.server.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.bbn.marti.mfa.MfaGateFilter;
import com.bbn.marti.mfa.MfaService;

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

	@Bean(name = "mfaGateFilter")
	public MfaGateFilter mfaGateFilter(MfaService mfaService) {
		return new MfaGateFilter(mfaService);
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
