import java.security.SecureRandom;
import java.util.Base64;
public class Authenticate {
    private static int SALT_SIZE = 16;

    //create salt for hashing
    public static String generateSalt(){
        SecureRandom scRand = new SecureRandom();
        byte[] salt_arr = new byte[SALT_SIZE];
        scRand.nextBytes(salt_arr); //create number of random bytes
        return Base64.getEncoder().encodeToString(salt_arr); // encodes bytes to string with base64 encoder
    }
}
