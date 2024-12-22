import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class Encryption {
    private static final String ALGO = "AES";
    private static final String TRANSFORM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 16;


    public SecretKey genKey() throws NoSuchAlgorithmException {
        KeyGenerator keyG = KeyGenerator.getInstance(ALGO);
        keyG.init(KEY_SIZE);
        return keyG.generateKey();
    }

    // new iv each time
    public byte[] encryptContainer(byte[] data, SecretKey key) throws GeneralSecurityException, IOException {
        byte[] ivBytes = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);

        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(data);

        // Combine IV + encrypted data
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(ivBytes);
        bos.write(encrypted);
        return bos.toByteArray();
    }

    public byte[] decryptContainer(byte[] cipherData, SecretKey key) throws GeneralSecurityException{
        // get iv first
        byte[] ivBytes = new byte[IV_SIZE];
        System.arraycopy(cipherData, 0, ivBytes, 0, IV_SIZE);

        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        // The rest is the actual encrypted content
        byte[] actualCipher = new byte[cipherData.length - IV_SIZE];
        System.arraycopy(cipherData, IV_SIZE, actualCipher, 0, actualCipher.length);

        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(actualCipher);
    }

    public SecretKey loadKeyIfExistOrGen(String metaPath) throws IOException, NoSuchAlgorithmException {
        String keyPath = metaPath + ".key.txt";
        File f = new File(keyPath);
        if (f.exists()) {
            return loadKey(keyPath);
        } else {
            SecretKey newKey = genKey();
            saveKey(newKey, keyPath);
            return newKey;
        }
    }

    public void saveKey(SecretKey key, String path) throws IOException {
        String encKey = Base64.getEncoder().encodeToString(key.getEncoded());
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(path))) {
            writer.write(encKey);
        }
    }

    public SecretKey loadKey(String path) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String encKey = reader.readLine();
            byte[] keyBytes = Base64.getDecoder().decode(encKey);
            return new SecretKeySpec(keyBytes, ALGO);
        }
    }

    public byte[] encrypt(byte[] data, SecretKey key, IvParameterSpec iv)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    public byte[] decrypt(byte[] data, SecretKey key, IvParameterSpec iv)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }
}
