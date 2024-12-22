import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

public class Vault {
    private static final long BLOCK_SIZE = 512L * 1024L * 1024L; // pad to this size
    private final String vaultPath;
    private final String metaPath;
    private final Encryption enc;
    private final Authenticate auth;

    // fileIndex: maps filename -> FileRecord (offset, length, iv, hash)
    private Map<String, FileRecord> fileIndex;

    private boolean unlocked;
    private SecretKey activeKey;

    public Vault(String vaultPath, String metaPath) {
        this.vaultPath = vaultPath;
        this.metaPath = metaPath;
        this.enc = new Encryption();
        this.auth = new Authenticate(metaPath);
        this.fileIndex = new HashMap<>();
        this.unlocked = false;
    }

    public void createVault(String password) {
        try {
            String salt = auth.generateSalt();
            auth.hashPass(password, salt, true);

            this.activeKey = enc.genKey();
            this.fileIndex.clear();

            lockVault(); // write out empty container
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean unlockVault(String password) {
        try {
            if (!auth.verify(password)) {
                return false;
            }
            this.activeKey = enc.loadKeyIfExistOrGen(metaPath);

            File vaultFile = new File(vaultPath);
            if (!vaultFile.exists() || vaultFile.length() == 0) {
                // new or empty container
                fileIndex.clear();
                unlocked = true;
                return true;
            }

            try (RandomAccessFile raf = new RandomAccessFile(vaultFile, "r")){
                long fileLength = raf.length();

                raf.seek(fileLength - 8); // 8 as last 8 bytes is the size of the encrypted index
                byte[] indexSizeBytes = new byte[8];
                raf.readFully(indexSizeBytes);
                long encryptedIndexSize = bytesToLong(indexSizeBytes);

                long encIndexOffset = fileLength - 8 - encryptedIndexSize;
                if(encIndexOffset < 0){
                    System.out.println("Corrupted vault: negative index offset.");
                    return false;
                }

                raf.seek(encIndexOffset);
                byte[] encIndexBytes = new byte[(int)encryptedIndexSize];
                raf.readFully(encIndexBytes);

                byte[] decIndexBytes = enc.decryptContainer(encIndexBytes, activeKey);

                Map<String, FileRecord> loadedIndex = deserializeIndex(decIndexBytes);
                if(loadedIndex == null){
                    System.out.println("Failed to deserialize index.");
                    return false;
                }

                this.fileIndex = loadedIndex;
                this.unlocked = true;
                System.out.println("Vault unlocked successfully.");
                return true;
            }

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     *   1) For each file in fileIndex, read old offset/length from existing vault, append it in memory (one by one)
     *   2) Pad up to specified size
     *   3) Write index and 8 byte header
     *   maybe make it so that it will round up !!!!!!!!!!!!!!!!!!!!!!!!!!!
     */
    public void lockVault() {
        if (!unlocked) {
            System.out.println("Vault is already locked or was never unlocked.");
            return;
        }
        try (RandomAccessFile raf = new RandomAccessFile(vaultPath, "rw")) {
            raf.seek(raf.length());

            ////// padding start
            long currentSize = raf.length();
            long desiredPaddedSize = BLOCK_SIZE;

            if(currentSize < desiredPaddedSize){
                long paddingSize = desiredPaddedSize - currentSize;
                System.out.println("Padding container to " + desiredPaddedSize + " bytes.");
                byte[] padding = new byte[(int)paddingSize];
                new SecureRandom().nextBytes(padding);
                raf.write(padding);
            //////// padding end
            }else{
                System.out.println("Container already at or above " + desiredPaddedSize + " bytes.");
            }

            // Serialize and encrypt the index
            byte[] serializedIndex = serializeIndex(fileIndex);
            byte[] encryptedIndex = enc.encryptContainer(serializedIndex, activeKey);

            // write index and header
            raf.write(encryptedIndex);
            raf.write(longToBytes(encryptedIndex.length));

            // Update state
            unlocked = false;
            fileIndex.clear();

            System.out.println("Vault locked successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // go to the end -> append enc data -> update index
    // check other alternatives
    public void addFile(String filePath) {
        if (!unlocked) {
            System.out.println("Vault is locked. Unlock first.");
            return;
        }
        try (RandomAccessFile raf = new RandomAccessFile(vaultPath, "rw")) {
            raf.seek(raf.length()); // Move to the end of the file
            long offset = raf.getFilePointer();

            File file = new File(filePath);
            if (!file.exists() || file.isDirectory()) {
                System.out.println("Invalid file path.");
                return;
            }
            byte[] plainData = Files.readAllBytes(file.toPath());
            //IvParameterSpec ivSpec = enc.genIv();
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            byte[] encryptedData = enc.encrypt(plainData, activeKey, new IvParameterSpec(iv));

            raf.write(encryptedData);

            // update index
            FileRecord record = new FileRecord(offset, encryptedData.length, iv, computeHash(plainData));
            fileIndex.put(file.getName(), record);

            System.out.println("File added to vault: " + file.getName());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // remove a file from the in-memory vault index
    public void removeFile(String logicalName) {
        if (!unlocked) {
            System.out.println("Vault is locked. Unlock first.");
            return;
        }
        FileRecord rec = fileIndex.remove(logicalName);
        if (rec != null) {
            System.out.println("File removed from in-memory vault index: " + logicalName);
        } else {
            System.out.println("No file found with name: " + logicalName);
        }
    }

    // !extract using offset!
    // header -> get index
    // index -> get offset
    // offset -> read file
    // offset ile tam konumu buluyoruz
    public void extractFile(String logicalName, String destinationPath) {
        if (!unlocked) {
            System.out.println("Vault is locked. Unlock first.");
            return;
        }
        FileRecord record = fileIndex.get(logicalName);
        if (record == null) {
            System.out.println("File not found in vault.");
            return;
        }
        try (RandomAccessFile raf = new RandomAccessFile(vaultPath, "r")) {
            raf.seek(record.offset);
            byte[] encryptedData = new byte[(int) record.length];
            raf.readFully(encryptedData);

            byte[] decryptedData = enc.decrypt(encryptedData, activeKey, new IvParameterSpec(record.iv));
            if (!computeHash(decryptedData).equals(record.hash)) {
                System.out.println("WARNING: Integrity check failed for " + logicalName);
                return;
            }

            Files.write(new File(destinationPath).toPath(), decryptedData);
            System.out.println("File extracted successfully to: " + destinationPath);

            //for removing after exract
            removeFile(logicalName);
            System.out.println("File successfully removed: " + logicalName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    // files in memory
    public void listFiles() {
        if (!unlocked) {
            System.out.println("Vault is locked. Unlock first.");
            return;
        }
        if (fileIndex.isEmpty()) {
            System.out.println("Vault is empty.");
            return;
        }
        System.out.println("Files in vault:");
        for (String logicalName : fileIndex.keySet()) {
            System.out.println(" - " + logicalName);
        }
    }

    public boolean isUnlocked() {
        return unlocked;
    }

    private String computeHash(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            return Base64.getEncoder().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] serializeIndex(Map<String, FileRecord> index) { // turn to byte
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(index);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, FileRecord> deserializeIndex(byte[] raw) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(raw);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            return (Map<String, FileRecord>) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static long bytesToLong(byte[] arr) {
        try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(arr))) {
            return dis.readLong();
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
    }

    private static byte[] longToBytes(long x) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(bos)) {
            dos.writeLong(x);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }


    // offset, length, IV, hash for each file

    // ??? maybe use transient for cipher data ???
    // transient for files temporary or should not be saved, sensitive

    private static class FileRecord implements Serializable {
        long offset;  // offset in container (valid after lockVault)
        long length;  // length of encrypted data
        byte[] iv;    // 16 byte IV
        String hash;  // Base64 encoded SHA-256 of plaintext

        public FileRecord(long offset, long length, byte[] iv, String hash) {
            this.offset = offset;
            this.length = length;
            this.iv = iv;
            this.hash = hash;
        }
    }
}
