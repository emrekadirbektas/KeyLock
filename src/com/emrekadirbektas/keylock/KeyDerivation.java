package com.emrekadirbektas.keylock;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class KeyDerivation {

    /**
     * Derives a 128-bit AES key from a common secret string (password).
     * The process is: secret -> SHA-256 hash -> truncate to 16 bytes -> AES key.
     *
     * @param commonSecret The shared secret string (e.g., a password).
     * @return A SecretKey for AES encryption.
     * @throws NoSuchAlgorithmException if SHA-256 is not available.
     */
    public static SecretKey deriveKeyFromPassword(String commonSecret) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(commonSecret.getBytes(StandardCharsets.UTF_8));
        byte[] keyBytes = Arrays.copyOf(hash, 16); // Use the first 16 bytes (128 bits) for the AES key.
        return new SecretKeySpec(keyBytes, "AES");
    }
}