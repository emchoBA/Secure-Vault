import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Vault {
    private final String vaultPath;
    private final String KEY_HASH = "Hash";

    public Vault(String vaultPath) {
        this.vaultPath = vaultPath;
    }

    public void saveEncFile(String fileName, byte[] data, SecretKey key) throws Exception {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] encData = new Encryption().encrypt(data, key, ivSpec);

        File encFile = new File(vaultPath + File.separator + fileName + ".enc");
        try (FileOutputStream fos = new FileOutputStream(encFile)) {
            fos.write(encData);
        }

        String fileHash = computeHash(encData); //check if needed for plain version

        System.out.println("IV: " + Base64.getEncoder().encodeToString(iv));

        String metadata = "Original_File_Name:" + fileName + "\n" +
                KEY_HASH+ ":" + fileHash + "\n" +
                "IV:" + Base64.getEncoder().encodeToString(iv);

        saveMeta(fileName, metadata);

        System.out.println("Encrypted file and metadata saved successfully.");
    }

    public byte[] loadEncFile(String fileName, Encryption enc, SecretKey key) throws Exception {
        File encFile = new File(vaultPath + File.separator + fileName + ".enc");
        byte[] data = new byte[(int) encFile.length()];
        try (FileInputStream fis = new FileInputStream(encFile)) {
            int test = fis.read(data); // Put int test for testing purposes does not do anything
        }

        String meta = loadMeta(fileName);
        String iv = extractMeta(meta, "IV");
        IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
        System.out.println("IV: " + ivSpec);
        return enc.decrypt(data, key, ivSpec);
    }

    private String computeHash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest mesDig = MessageDigest.getInstance("SHA-256");
        byte[] hash = mesDig.digest(data);
        return Base64.getEncoder().encodeToString(hash);
    }
    //make it so it check decrypted version of file
    public boolean verifyIntegrity(String fileName, byte[] data) throws Exception{
        String currHash = computeHash(data);
        String meta = loadMeta(fileName);
        String storeHash = extractMeta(meta, KEY_HASH);
        return currHash.equals(storeHash);
    }

    private void saveMeta(String fileName, String meta) throws IOException {
        File metaFile = new File (vaultPath + File.separator + fileName + ".meta");
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(metaFile))) {
            writer.write(meta);
        }
    }

    private String loadMeta(String fileName) throws IOException {
        File metaFile = new File(vaultPath + File.separator + fileName + ".meta");
        StringBuilder meta = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(metaFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                meta.append(line).append("\n");
            }
        }
        return meta.toString().trim();
    }

    private String extractMeta(String meta, String key) {
        String[] lines = meta.split("\n");
        for (String line : lines) {
            if (line.startsWith(key + ":")) {
                return line.split(":", 2)[1];
            }
        }
        return null;
    }


}
