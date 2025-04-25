package com.emrekadirbektas.keylock;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class FileEncryptor {

    // AES/CBC/PKCS5Padding şifreleme dönüşümünü tanımlar.
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    // AES için kullanılacak algoritma adı.
    private static final String ALGORITHM = "AES";
    // AES için 128-bit anahtar (16 byte).
    private static final int KEY_LENGTH_BYTES = 16;
    // AES/CBC için 16 byte'lık Başlatma Vektörü (IV).
    private static final int IV_LENGTH_BYTES = 16;

    /**
     * Bir dosyayı AES/CBC/PKCS5Padding kullanarak şifreler.
     * Her şifreleme işlemi için rastgele bir Başlatma Vektörü (IV) oluşturulur
     * ve şifrelenmiş dosyanın başına eklenir (IV + ciphertext).
     *
     * @param inputPath  Şifrelenecek dosyanın yolu.
     * @param outputPath Şifrelenmiş dosyanın yazılacağı yol.
     * @param secretKey  Şifreleme için kullanılacak 128-bit (16 byte) AES anahtarı.
     * @throws GeneralSecurityException Şifreleme veya dosya G/Ç sırasında bir hata oluşursa.
     * @throws IllegalArgumentException Eğer sağlanan anahtar 16 byte değilse.
     */
    public static void encryptFile(String inputPath, String outputPath, byte[] secretKey) throws GeneralSecurityException {
        // Anahtar uzunluğunu doğrula. AES-128 için 16 byte olmalıdır.
        if (secretKey == null || secretKey.length != KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException("Geçersiz anahtar boyutu. Anahtar " + KEY_LENGTH_BYTES + " byte olmalıdır.");
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, ALGORITHM);

        // Güvenli bir şekilde rastgele 16 byte'lık bir IV oluştur.
        byte[] iv = new byte[IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        // Dosya akışlarını yönetmek için try-with-resources kullan.
        try (InputStream in = new FileInputStream(inputPath); OutputStream out = new FileOutputStream(outputPath)) {
            // IV'yi şifreli dosyanın başına yaz.
            out.write(iv);
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                // Dosyayı parçalar halinde şifrele ve yaz.
                out.write(cipher.update(buffer, 0, bytesRead));
            }
            // Kalan son bloğu şifrele ve yaz.
            out.write(cipher.doFinal());
        } catch (java.io.IOException e) {
            // IOException'ı daha genel bir kripto istisnasına sarmala.
            throw new GeneralSecurityException("Şifreleme sırasında dosya G/Ç hatası.", e);
        }
    }
}