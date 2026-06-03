package com.bbn.marti.remote.config;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Test;

import com.bbn.marti.config.Configuration;

/**
 * Verifies the test-only seam on {@link CoreConfigFacade}: {@code setInstanceForTesting} installs a
 * facade backed by a fixed {@link Configuration} so unit tests can read config without booting
 * Apache Ignite (which otherwise blocks the test worker for minutes). See rearchitecture area #8.
 */
public class CoreConfigFacadeTest {

    @After
    public void tearDown() {
        // do not leak singleton state into other tests
        CoreConfigFacade.clearInstanceForTesting();
    }

    @Test
    public void setInstanceForTesting_returnsInjectedConfig_withoutBootingIgnite() {
        Configuration cfg = new Configuration();

        long start = System.nanoTime();
        CoreConfigFacade.setInstanceForTesting(cfg);
        CoreConfigFacade facade = CoreConfigFacade.getInstance();
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;

        assertNotNull("getInstance() must return the pre-installed test facade", facade);
        assertSame("remote configuration must be the injected instance", cfg, facade.getRemoteConfiguration());
        assertSame("cached configuration must be the injected instance", cfg, facade.getCachedConfiguration());

        // The Ignite-booting constructor would take on the order of minutes; the seam must not run it.
        assertTrue("test facade install + read must be effectively instantaneous (was " + elapsedMillis
                + " ms) — Ignite must not boot", elapsedMillis < 5_000L);
    }

    @Test
    public void clearInstanceForTesting_dropsInstalledInstance() {
        Configuration first = new Configuration();
        CoreConfigFacade.setInstanceForTesting(first);
        assertSame(first, CoreConfigFacade.getInstance().getRemoteConfiguration());

        Configuration second = new Configuration();
        CoreConfigFacade.setInstanceForTesting(second);
        assertSame("re-installing must replace the prior test instance", second,
                CoreConfigFacade.getInstance().getRemoteConfiguration());
    }
}
