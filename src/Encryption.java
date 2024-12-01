import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Encryption {
    private static final String ALGO = "AES";
    private static final String TRANSFORM = "AES/CBC/PKCS5Padding"; // transformation for usage of iv and padding
    private static final int KEY_SIZE = 256; //AES-256 key size
    private static final int BLOCK_SIZE = 16; // AES block size

//    public static SecretKey genKey(){
//        try {
//            KeyGenerator keyG = KeyGenerator.getInstance(ALGO);
//            keyG.init(KEY_SIZE);
//            return keyG.generateKey();
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        }
//    }
    // USE PASSWORD DERIVATION FOR ENC KEY

    public static IvParameterSpec genIv(){ // can be byte[] genIv()
        byte[] iv = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(iv); // like generating salt, cbc
        return new IvParameterSpec(iv);
    }

    public static byte[] encrypt(byte[] data, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException { //can be String input
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }
}
