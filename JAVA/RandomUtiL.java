import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Calendar;

public class RandomUtil {

    private RandomUtil() {
	throw new IllegalStateException("Utility class");
    }

    // Método para generar una contraseña alfanumérica aleatoria de una longitud
    // específica
    public static String generateRandomPassword(int len) {
	// Rango ASCII – alfanumérico (0-9, a-z, A-Z)
	final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

	SecureRandom random = new SecureRandom();
	try {
	    random = SecureRandom.getInstanceStrong();
	} catch (NoSuchAlgorithmException ex) {
	    ex.printStackTrace();
	}
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

	SecureRandom random = new SecureRandom();
	try {
	    random = SecureRandom.getInstanceStrong();
	} catch (NoSuchAlgorithmException ex) {
	    ex.printStackTrace();
	}
	return random.nextInt((max - min) + 1) + min;
    }

    public static Timestamp generateRamdomTimestamp() {
	long offset = Timestamp.valueOf("2010-01-01 00:00:00").getTime();
	long end = Calendar.getInstance().getTimeInMillis();
	long diff = end - offset + 1;
	return new Timestamp(offset + (long) (Math.random() * diff));
    }

    public static String parseDateToString(Timestamp date) {
	SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	if (date == null)
	    return "";
	return df.format(date);
    }
}