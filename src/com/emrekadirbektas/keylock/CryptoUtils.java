package com.emrekadirbektas.keylock;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Utility class for cryptographic operations like AES encryption and decryption.
 */
public class CryptoUtils {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int AES_KEY_SIZE = 256; // bits
    private static final int IV_SIZE = 16; // 16 bytes for AES

    /**
     * Derives a fixed-size key from the shared secret using SHA-256.
     *
     * @param sharedSecret The BigInteger shared secret from Diffie-Hellman.
     * @return A byte array suitable for use as an AES key.
     * @throws Exception if the hashing algorithm is not found.
     */
    private static byte[] deriveKey(BigInteger sharedSecret) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] sharedSecretBytes = sharedSecret.toByteArray();
        byte[] key = sha.digest(sharedSecretBytes);
        // Truncate the key to the required size (32 bytes for AES-256)
        return Arrays.copyOf(key, AES_KEY_SIZE / 8);
    }

    /**
     * Encrypts a plaintext message using the shared secret.
     *
     * @param plainText    The message to encrypt.
     * @param sharedSecret The shared secret key.
     * @return A Base64 encoded string containing the IV and the ciphertext.
     * @throws Exception for any cryptographic errors.
     */
    public static String encrypt(String plainText, BigInteger sharedSecret) throws Exception {
        byte[] keyBytes = deriveKey(sharedSecret);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, ALGORITHM);

        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        byte[] ivAndCipherText = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, ivAndCipherText, 0, iv.length);
        System.arraycopy(cipherText, 0, ivAndCipherText, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(ivAndCipherText);
    }

    /**
     * Decrypts a message using the shared secret.
     *
     * @param encryptedString The Base64 encoded string (IV + ciphertext).
     * @param sharedSecret    The shared secret key.
     * @return The original plaintext message.
     * @throws Exception for any cryptographic errors.
     */
    public static String decrypt(String encryptedString, BigInteger sharedSecret) throws Exception {
        byte[] ivAndCipherText = Base64.getDecoder().decode(encryptedString);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivAndCipherText, 0, IV_SIZE);
        byte[] keyBytes = deriveKey(sharedSecret);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, ALGORITHM);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(ivAndCipherText, IV_SIZE, ivAndCipherText.length - IV_SIZE);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}