package tak.server.util;

public class UsernameUtils {
	
	public static final String ERROR_MESSAGE_FOR_INVALID_USERNAME = "Username is invalid. Username requirements: minimum of 4 characters and contains only letters, numbers, dots, underscores and hyphens.";

	/**
	 * The bootstrap administrator account. It must never be removable through the
	 * user-management or onboarding flows, otherwise an operator can lock everyone
	 * out of the server. Compared case-insensitively.
	 */
	public static final String PROTECTED_ADMIN_USERNAME = "takadmin";

	/** @return true if {@code username} refers to the protected bootstrap admin account. */
	public static boolean isProtectedAdmin(String username) {
		return username != null && PROTECTED_ADMIN_USERNAME.equalsIgnoreCase(username.trim());
	}

	public static boolean isValidUsername(String username) {
		
		if (username == null) {
			return false;
		}
		
		if (username.length() < 4) {
			return false;
		}
		
		if (!username.matches("^[a-zA-Z0-9_.\\-]+$")) {
			return false;
		} 
		
		return true;
	}
	
}
