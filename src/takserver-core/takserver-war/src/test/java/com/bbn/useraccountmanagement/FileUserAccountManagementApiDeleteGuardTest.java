package com.bbn.useraccountmanagement;

import static org.junit.Assert.fail;

import org.junit.Test;

import com.bbn.marti.remote.exception.ForbiddenException;

/**
 * Verifies the protected-admin guard in
 * {@link FileUserAccountManagementApi#deleteUser}. The guard runs before the
 * autowired user-management backend is touched, so it can be exercised on a
 * bare instance: a protected username must be rejected with ForbiddenException
 * and never reach the removal backend.
 */
public class FileUserAccountManagementApiDeleteGuardTest {

	@Test
	public void deleteUser_rejectsProtectedAdmin() {
		FileUserAccountManagementApi api = new FileUserAccountManagementApi();
		try {
			api.deleteUser("takadmin");
			fail("expected ForbiddenException deleting the protected admin user");
		} catch (ForbiddenException expected) {
			// pass — and the (unset) backend was never invoked
		}
	}

	@Test
	public void deleteUser_rejectsProtectedAdminCaseInsensitive() {
		FileUserAccountManagementApi api = new FileUserAccountManagementApi();
		try {
			api.deleteUser("TAKADMIN");
			fail("expected ForbiddenException deleting the protected admin user");
		} catch (ForbiddenException expected) {
			// pass
		}
	}
}
