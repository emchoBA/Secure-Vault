import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
public class Authenticate {
    // I did this part using specifications from project file, such as hashing with salt and usage of AES-256
    private static final int SALT_SIZE = 16;
    private static final String ALGO = "SHA-256";

    //create salt for hashing
    public static String generateSalt(){
        SecureRandom scRand = new SecureRandom();
        byte[] salt_arr = new byte[SALT_SIZE];
        scRand.nextBytes(salt_arr); //create number of random bytes
        return Base64.getEncoder().encodeToString(salt_arr); // encodes bytes to string with base64 encoder
    }

    public static String hashPass(String pass, String salt){
        try {
            MessageDigest mesDig = MessageDigest.getInstance(ALGO); // selected algorithm
            mesDig.update(Base64.getDecoder().decode(salt)); // because MessageDigest works with binary
            // update puts salt to hash input
            byte[] hashedPass = mesDig.digest(pass.getBytes()); // turned to byte, hashed with salt
            return Base64.getEncoder().encodeToString(hashedPass);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
