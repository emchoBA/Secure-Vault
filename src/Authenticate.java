import java.io.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class Authenticate {
    private static final int SALT_SIZE = 16;
    private static final String ALGO = "SHA-256";
    private final String metaPath;

    public Authenticate(String metaPath) {
        this.metaPath = metaPath;
    }

    public String generateSalt() {
        SecureRandom scRand = new SecureRandom();
        byte[] saltBytes = new byte[SALT_SIZE];
        scRand.nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }


    public String hashPass(String pass, String salt, boolean store) {
        try {
            MessageDigest md = MessageDigest.getInstance(ALGO);
            md.update(Base64.getDecoder().decode(salt));
            byte[] hashedPassBytes = md.digest(pass.getBytes());
            String hashedPassStr = Base64.getEncoder().encodeToString(hashedPassBytes);
            if (store) {
                storeCredentials(hashedPassStr, salt);
            }
            return hashedPassStr;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public boolean verify(String pass) {
        try {
            String info = loadCredentials();
            if (info == null) {
                return false;
            }
            String storedHash = extractInfo(info, "Hash");
            String storedSalt = extractInfo(info, "Salt");

            // rehash pass with salt
            String testHash = hashPass(pass, storedSalt, false);
            return testHash.equals(storedHash);
        } catch (Exception e) {
            return false;
        }
    }

    private void storeCredentials(String hashedPass, String salt) throws IOException {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(metaPath))) {
            bw.write("Hash:" + hashedPass + "\n");
            bw.write("Salt:" + salt + "\n");
        }
    }

    private String loadCredentials() {
        File f = new File(metaPath);
        if (!f.exists()) return null;
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
        } catch (Exception e) {
            return null;
        }
        return sb.toString().trim();
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
