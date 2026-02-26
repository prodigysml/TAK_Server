package tak.server.util;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.RandomStringUtils;

public class PasswordUtils {
	
	private static final String SPECIAL_CHARS_PATTERN = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[-_!@#$%^&*(){}+=~`|:;<>,./?\\[\\]\\\\])(?=[^'\"]+$)(?=\\S+$).{15,}$";
	private static final String SPECIAL_CHARS_GENERATION = "-_!@#$%^&+=~|:;,.?";
	public static final String FAILED_COMPLEXITY_CHECK_ERROR_MESSAGE = "Password complexity check failed. Password must be a minimum of 15 characters including 1 uppercase, 1 lowercase, 1 number, and 1 special character from this list [-_!@#$%^&*(){}[]+=~`|:;<>,./?].";
	
	
	public static boolean isValidPassword(String password) {
		if (password == null) {
			return false;
		}
		Pattern pattern = Pattern.compile(SPECIAL_CHARS_PATTERN);
		Matcher matcher = pattern.matcher(password);
		return matcher.matches();
	}
	
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static String generatePassword() {
        String upperCaseLetters = RandomStringUtils.random(3, 65, 90, true, true, null, SECURE_RANDOM);
        String lowerCaseLetters = RandomStringUtils.random(3, 97, 122, true, true, null, SECURE_RANDOM);
        String numbers = RandomStringUtils.random(3, 0, 0, false, true, null, SECURE_RANDOM);
        String totalChars = RandomStringUtils.random(3, 0, 0, true, true, null, SECURE_RANDOM);

        String specialChars = "";
        for (int count = 0; count < 3; count ++) {
        	int random_int = SECURE_RANDOM.nextInt(SPECIAL_CHARS_GENERATION.length());
        	specialChars += SPECIAL_CHARS_GENERATION.charAt(random_int);
        }

        String combinedChars = upperCaseLetters.concat(lowerCaseLetters)
                .concat(numbers)
                .concat(totalChars)
                .concat(specialChars);
        List<Character> pwdChars = combinedChars.chars()
                .mapToObj(c -> (char) c)
                .collect(Collectors.toList());
        Collections.shuffle(pwdChars, SECURE_RANDOM);
        String password = pwdChars.stream()
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();
        return password;
    }

}
