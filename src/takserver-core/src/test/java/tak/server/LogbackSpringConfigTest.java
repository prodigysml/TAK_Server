package tak.server;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.AfterClass;
import org.junit.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.logging.LoggingInitializationContext;
import org.springframework.boot.logging.LoggingSystem;
import org.springframework.core.env.StandardEnvironment;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.util.ContextInitializer;

/**
 * Spring Boot treats any logback config error as fatal, so a logback release
 * that reads logback-spring.xml differently stops every TAK process at startup
 * (1.5.37 stopped registering appenders defined inside <if> blocks). Load the
 * real config under each profile TAK runs with so that shows up in the build.
 */
public class LogbackSpringConfigTest {

	private static void load(String... profiles) throws Exception {
		Path logs = Files.createTempDirectory("logback-config-test");
		System.setProperty("LOG_PATH", logs.toString());
		StandardEnvironment env = new StandardEnvironment();
		env.setActiveProfiles(profiles);
		LoggingSystem logging = LoggingSystem.get(LogbackSpringConfigTest.class.getClassLoader());
		logging.beforeInitialize();
		// Throws IllegalStateException listing the errors when the config is bad.
		logging.initialize(new LoggingInitializationContext(env), "classpath:logback-spring.xml", null);
		logging.cleanUp();
	}

	@Test
	public void configProfile() throws Exception {
		load("config");
	}

	@Test
	public void apiProfile() throws Exception {
		load("api");
	}

	@Test
	public void messagingProfile() throws Exception {
		load("messaging");
	}

	@Test
	public void monolithProfile() throws Exception {
		load("monolith");
	}

	// Put back the default logging setup for the other tests in this JVM.
	@AfterClass
	public static void resetLogging() throws Exception {
		System.clearProperty("LOG_PATH");
		LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
		context.reset();
		new ContextInitializer(context).autoConfig();
	}
}
