import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Vault {
    private final String vaultPath;
    private final Encryption enc = new Encryption();

    private boolean isLocked;
    private final String KEY_HASH = "Hash";


    public Vault(String vaultPath) {
        this.vaultPath = vaultPath;
        this.isLocked = false;
    }

    public void unlockVault(String pass) throws Exception {
        if(!isLocked){
            System.out.println("Vault is already unlocked.");
        }else {
            Authenticate aut = new Authenticate(vaultPath);

            if (aut.verify(pass)) {
                //decryptVault();////////////////////
                isLocked = false;
                System.out.println("Vault unlocked successfully.");
                return;
            }
            System.out.println("Vault could not be unlocked.");
        }
    }

    public void lockVault() throws Exception {
        if(!isLocked){
            //encryptVault();
            isLocked = true;
            System.out.println("Vault locked successfully.");
        }else {
            System.out.println("Vault is already locked.");
        }
    }

    public void saveEncFile(String fileName, byte[] data, SecretKey key) throws Exception {
        if (isLocked) {
            throw new IllegalStateException("Vault is locked. File cannot be loaded.");
        }

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] encData = enc.encrypt(data, key, ivSpec);

        File encFile = new File(vaultPath + File.separator + fileName + ".enc");
        try (FileOutputStream fos = new FileOutputStream(encFile)) {
            fos.write(encData);
        }

        String fileHash = computeHash(data); //do this with salted version

        String metadata = "Original_File_Name:" + fileName + "\n" +
                KEY_HASH+ ":" + fileHash + "\n" +
                "IV:" + Base64.getEncoder().encodeToString(iv);

        saveMeta(fileName, metadata);

        System.out.println("Encrypted file and metadata saved successfully.");
    }

    public byte[] loadEncFile(String fileName, SecretKey key) throws Exception {
        if(isLocked){
            throw new IllegalStateException("Vault is locked. File cannot be loaded.");
        }

        File encFile = new File(vaultPath + File.separator + fileName + ".enc");
        byte[] data = new byte[(int) encFile.length()];
        try (FileInputStream fis = new FileInputStream(encFile)) {
            int test = fis.read(data); // Put int test for testing purposes does not do anything
        }

        String meta = loadMeta(fileName);
        String iv = extractMeta(meta, "IV");
        IvParameterSpec ivSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
        return enc.decrypt(data, key, ivSpec);
    }

    private String computeHash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest mesDig = MessageDigest.getInstance("SHA-256");
        byte[] hash = mesDig.digest(data);
        return Base64.getEncoder().encodeToString(hash);
    }
    public boolean verifyIntegrity(String fileName, byte[] data) throws Exception{
        //try to add salted version to computed hash
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

    private void encryptVault() throws Exception{
        File vault = new File(vaultPath);
        for(File file : vault.listFiles()){
            if(!file.getName().endsWith(".enc") && !file.getName().equals("key.txt") && !file.getName().equals("hash.meta")){
                byte[] fileData = Files.readAllBytes(file.toPath());
                SecretKey key = enc.loadKey(vaultPath +"\\key.txt");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                System.out.println("enc key: "+key);
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encData = cipher.doFinal(fileData);
                try(FileOutputStream fos = new FileOutputStream(file)) {
                    fos.write(encData);
                }
            }
        }
    }

    private void decryptVault() throws Exception{
        File vault = new File(vaultPath);
        for(File file : vault.listFiles()){
            if(file.getName().endsWith(".enc") && !file.getName().equals("key.txt") && !file.getName().equals("hash.meta")){
                byte[] fileData = Files.readAllBytes(file.toPath());
                SecretKey key = enc.loadKey(vaultPath +"\\key.txt");
                System.out.println(key);
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] decData = cipher.doFinal(fileData);
                try(FileOutputStream fos = new FileOutputStream(file)) {
                    fos.write(decData);
                }
            }
        }
    }


}
