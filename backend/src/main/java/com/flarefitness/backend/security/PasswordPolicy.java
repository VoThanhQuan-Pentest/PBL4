package com.flarefitness.backend.security;

import com.flarefitness.backend.exception.BadRequestException;
import org.springframework.stereotype.Component;

/**
 * Applies the password policy at the service boundary as well as through DTO
 * validation.  Service-level validation prevents callers that do not go
 * through an HTTP controller from bypassing the policy.
 */
@Component
public class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 128;

    private static final java.util.List<String> CONTEXT_WORDS = contextWords();

    public void validateNewPassword(String password) {
        int length = password == null ? 0 : password.codePointCount(0, password.length());
        if (password == null || password.isBlank() || length < MIN_LENGTH || length > MAX_LENGTH) {
            throw new BadRequestException(
                    "Mat khau phai co tu %d den %d ky tu.".formatted(MIN_LENGTH, MAX_LENGTH));
        }
        if (PasswordBlocklist.contains(password)) {
            throw new BadRequestException("Mat khau nay nam trong danh sach mat khau pho bien/da bi lo. Hay chon cum mat khau khac.");
        }
        String folded = java.text.Normalizer.normalize(password, java.text.Normalizer.Form.NFKC).toLowerCase(java.util.Locale.ROOT);
        String simple = folded.replaceAll("[^a-z0-9]", "");
        String leet = leet(folded).replaceAll("[^a-z0-9]", "");
        if (CONTEXT_WORDS.stream().anyMatch(word -> simple.contains(word) || leet.contains(leet(word)))) {
            throw new BadRequestException("Khong dung ten chuong trinh/du an trong mat khau.");
        }
    }

    private static String leet(String value) {
        return value.replace('0', 'o').replace('1', 'i').replace('3', 'e').replace('4', 'a')
                .replace('5', 's').replace('7', 't').replace('@', 'a').replace('$', 's');
    }
    private static java.util.List<String> contextWords() {
        try (var input = PasswordPolicy.class.getResourceAsStream("/security/password-context-words.txt")) {
            if (input == null) throw new IllegalStateException("Required password context word list is missing");
            var words = new String(input.readNBytes(4097), java.nio.charset.StandardCharsets.UTF_8).lines()
                    .filter(line -> !line.isBlank()).toList();
            if (words.isEmpty() || words.size() > 32 || words.stream().anyMatch(word -> !word.matches("[a-z0-9]{3,40}")))
                throw new IllegalStateException("Invalid password context word list");
            return java.util.List.copyOf(words);
        } catch (java.io.IOException failure) { throw new IllegalStateException("Cannot load password context words", failure); }
    }
}
