import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

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