import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Main {


    public static void main(String[] args) {
        String path = "D:\\vault";

        System.out.println("Authenticate");
        Authenticate aut = new Authenticate();
        String salt = aut.generateSalt();
        String pass = "deneme";
        String hashedPass = aut.hashPass(pass, salt);
        boolean verify = aut.verify(pass, salt, hashedPass);

        System.out.println("Salt pass: " + hashedPass + " " + salt);
        System.out.println("Compare: " + verify);
        System.out.println("//////////////////////////");

        System.out.println("Encryption");
        Encryption enc = new Encryption();
        IvParameterSpec iv = enc.genIv();
        try {
            SecretKey key = enc.genKey();

            enc.saveKey(key, path + "\\key.txt");
            SecretKey key2 = enc.loadKey(path + "\\key.txt");
            System.out.println("Key: " + key + " " + key2 + " " + iv);
            System.out.println("//////////////////////////");

            String data = "deneme";
            System.out.println("iv" + iv);
            byte[] encData = enc.encrypt(data.getBytes(), key, iv);
            byte[] decData = enc.decrypt(encData, key, iv);
            System.out.println("Data: " + data + " " + new String(decData));
            System.out.println("//////////////////////////");

        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("Vault");
        Vault vault = new Vault(path);

        try {
            String fileName = "deneme";
            byte[] data = "deneme".getBytes();
            SecretKey key = enc.loadKey(path + "\\key.txt");

            vault.saveEncFile(fileName, data, key);
            System.out.println("Key: " + key);
            byte[] decData = vault.loadEncFile(fileName, enc, key);
            System.out.println("Data: " + new String(data) + " " + new String(decData));
            System.out.println("//////////////////////////");

            boolean verifyIntegrity = vault.verifyIntegrity(fileName, data);
            System.out.println("Verify: " + verifyIntegrity);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}