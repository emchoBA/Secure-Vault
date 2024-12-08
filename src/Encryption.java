import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileReader;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {
    private static final String ALGO = "AES";
    private static final String TRANSFORM = "AES/CBC/PKCS5Padding"; // transformation for usage of iv and padding
    private static final int KEY_SIZE = 256; //AES-256 key size
    private static final int BLOCK_SIZE = 16; // IV block size

    public SecretKey genKey() throws NoSuchAlgorithmException{
            KeyGenerator keyG = KeyGenerator.getInstance(ALGO);
            keyG.init(KEY_SIZE);
            return keyG.generateKey();
        }
     //!!!!USE PASSWORD DERIVATION FOR ENC KEY

    public IvParameterSpec genIv(){ // can be byte[] genIv()
        byte[] iv = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(iv); // like generating salt, cbc
        return new IvParameterSpec(iv);
    }

    public void saveKey(SecretKey key, String path) throws IOException {
        String encKey = Base64.getEncoder().encodeToString(key.getEncoded());
        BufferedWriter writer = new BufferedWriter(new FileWriter(path));
        writer.write(encKey);
        writer.close();
    }

    public SecretKey loadKey(String path) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(path));
        String encKey = reader.readLine();
        byte[] key = Base64.getDecoder().decode(encKey);
        return new SecretKeySpec(key, ALGO);
    }

    public byte[] encrypt(byte[] data, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException { //can be String input
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    public byte[] decrypt(byte[] data, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }
}
