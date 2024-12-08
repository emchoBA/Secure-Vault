import java.io.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
public class Authenticate {
    // I did this part using specifications from project file, such as hashing with salt and usage of AES-256
    private static final int SALT_SIZE = 16;
    // private static final int ITER = 1000; // for PBKDF2WithHmacSHA256
    private static final String ALGO = "SHA-256";// change this to PBKDF2WithHmacSHA256
    private final String path;
    private String salt;

    public Authenticate(String path) {
        this.path = path;
    }
    //create salt for hashing
    public String generateSalt(){
        SecureRandom scRand = new SecureRandom();
        byte[] salt_arr = new byte[SALT_SIZE];
        scRand.nextBytes(salt_arr); //create number of random bytes
        String salt = Base64.getEncoder().encodeToString(salt_arr); // encodes bytes to string with base64 encoder
        this.salt = salt;
        return salt; // encodes bytes to string with base64 encoder
    }

    public String hashPass(String pass, String salt, boolean store) {
        try {
            MessageDigest mesDig = MessageDigest.getInstance(ALGO); // selected algorithm
            mesDig.update(Base64.getDecoder().decode(salt)); // because MessageDigest works with binary
            // update puts salt to hash input
            byte[] hashedPass = mesDig.digest(pass.getBytes()); // turned to byte, hashed with salt
            String hashedPassStr = Base64.getEncoder().encodeToString(hashedPass); // encodes bytes to string with base64 encoder
            if(store){
                storeInfo(hashedPassStr);
            }

            return hashedPassStr;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verify(String pass){
        String info = loadInfo();
        assert info != null;
        String hashedPass = extractInfo(info, "Hash");
        String saltVer = extractInfo(info, "Salt");

        String testHash = hashPass(pass, saltVer, false);
        return testHash.equals(hashedPass);
        // if done correctly returns true because algo is deterministic
    }

    private void storeInfo(String hashedPass) throws Exception {
        String hashPath = path + "\\hash.meta";
        BufferedWriter writer = new BufferedWriter(new FileWriter(hashPath));
        String fill = "Hash:" + hashedPass + "\n" + "Salt:" + salt;
        writer.write(fill);
        writer.close();
    }

    private String loadInfo() {
        File hashFile = new File(path + "\\hash.meta");
        if (hashFile.exists()) {
            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new FileReader(hashFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                return sb.toString().trim();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return null;
    }

    private String extractInfo(String info, String key) {
        String[] lines = info.split("\n");
        for (String line : lines) {
            if (line.startsWith(key + ":")) {
                return line.split(":", 2)[1];
            }
        }
        return null;
    }
}
