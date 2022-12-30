import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import lombok.SneakyThrows;

public class EncryptorAesGcmPassword {

    private EncryptorAesGcmPassword() {
	throw new IllegalStateException("Utility class");
    }

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";

    private static final int GCM_TAG_LENGTH = 16;
    private static final int IV_LENGTH_BYTE = 16;
    private static final int SALT_LENGTH_BYTE = 64;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    public static byte[] generateIv(int n) {
	byte[] iv = new byte[n];
	new SecureRandom().nextBytes(iv);
	return iv;
    }

    public static SecretKey getKeyFromPassword(String masterKey, byte[] salt)
	    throws NoSuchAlgorithmException, InvalidKeySpecException {

	SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
	KeySpec spec = new PBEKeySpec(masterKey.toCharArray(), salt, 2145, 256);
	return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    public static byte[] encryptHelper(String algorithm, String input, SecretKey key, GCMParameterSpec gcmParameterSpec)
	    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
	    InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

	Cipher cipher = Cipher.getInstance(algorithm);
	cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
	return cipher.doFinal(input.getBytes());
    }

    @SneakyThrows
    public static String decryptHelper(String algorithm, byte[] cipherText, byte[] tag, SecretKey key,
	    GCMParameterSpec gcmParameterSpec) {
	Cipher cipher = Cipher.getInstance(algorithm);
	cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
	cipher.update(cipherText);
	byte[] plainText = cipher.doFinal(tag);
	return new String(plainText, UTF_8);
    }

    public static String encrypt(String text, String masterKey) {
	try {
	    byte[] iv = generateIv(IV_LENGTH_BYTE);
	    byte[] salt = generateIv(SALT_LENGTH_BYTE);
	    SecretKey key = getKeyFromPassword(masterKey, salt);
	    byte[] cipher = encryptHelper(ENCRYPT_ALGO, text, key, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));
	    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
	    byte[] ciphertext = Arrays.copyOfRange(cipher, 0, text.length());
	    byte[] tag = Arrays.copyOfRange(cipher, text.length(), cipher.length);
	    outputStream.write(salt);
	    outputStream.write(iv);
	    outputStream.write(tag);
	    outputStream.write(ciphertext);
	    return Base64.getEncoder().encodeToString(outputStream.toByteArray());
	} catch (Exception e) {
	    e.printStackTrace();
	    return null;
	}
    }

    public static String decrypt(String encData, String masterKey) {
	try {
	    byte[] cipherText = Base64.getDecoder().decode(encData.getBytes(UTF_8));
	    byte[] salt = Arrays.copyOfRange(cipherText, 0, 64);
	    byte[] iv = Arrays.copyOfRange(cipherText, 64, 80);
	    byte[] tag = Arrays.copyOfRange(cipherText, 80, 96);
	    byte[] cipherTextTwo = Arrays.copyOfRange(cipherText, 96, cipherText.length);
	    SecretKey key = getKeyFromPassword(masterKey, salt);
	    return decryptHelper(ENCRYPT_ALGO, cipherTextTwo, tag, key, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));
	} catch (Exception e) {
	    e.printStackTrace();
	    return null;
	}
    }
}