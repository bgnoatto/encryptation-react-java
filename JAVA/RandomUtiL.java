import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Objects;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;

public class RandomUtil {

    // Método para generar una contraseña alfanumérica aleatoria de una longitud
    // específica
    public String generateRandomPassword(int len) {
	// Rango ASCII – alfanumérico (0-9, a-z, A-Z)
	final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

	SecureRandom random = new SecureRandom();
	StringBuilder sb = new StringBuilder();

	// cada iteración del bucle elige aleatoriamente un carácter del dado
	// rango ASCII y lo agrega a la instancia `StringBuilder`

	for (int i = 0; i < len; i++) {
	    int randomIndex = random.nextInt(chars.length());
	    sb.append(chars.charAt(randomIndex));
	}

	return sb.toString();
    }

    public static int getRandomNumberInRange(int min, int max) {

	if (min >= max) {
	    throw new IllegalArgumentException("max must be greater than min");
	}

	Random r = new Random();
	return r.nextInt((max - min) + 1) + min;
    }

}