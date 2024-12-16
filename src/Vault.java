import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

public class Vault {
    private static final long BLOCK_SIZE = 512L * 1024L * 1024L; // 512 MB
    private final String vaultPath;  // Single container file
    private final String metaPath;   // Path to hashed password + salt metadata
    private final Encryption enc;
    private final Authenticate auth;
    private Map<String, FileEntry> manifest;
    private boolean unlocked;
    private SecretKey activeKey;

    // Constructor
    public Vault(String vaultPath, String metaPath) {
        this.vaultPath = vaultPath;
        this.metaPath = metaPath;
        this.enc = new Encryption();
        this.auth = new Authenticate(metaPath);  // changed usage to store meta in metaPath
        this.manifest = new HashMap<>();
        this.unlocked = false;
    }

    public void createVault(String password) {
        try {
            // Generate and store salted hash (plus store salt in meta file)
            String salt = auth.generateSalt();
            String hashedPass = auth.hashPass(password, salt, true);

            // enc key
            this.activeKey = enc.genKey();

            // start with empty manifest
            this.manifest.clear();

            // Lock vault immediately, writing out an empty encrypted container
            lockVault();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean unlockVault(String password) {
        try {
            // Verify password against stored hash
            if (!auth.verify(password)) {
                return false;
            }

            this.activeKey = enc.loadKeyIfExistOrGen(metaPath);

            // Decrypt the single container file if it exists
            File vaultFile = new File(vaultPath);
            if (!vaultFile.exists() || vaultFile.length() == 0) {
                manifest.clear();
                unlocked = true;
                return true;
            }

            byte[] blob = Files.readAllBytes(vaultFile.toPath());
            if (blob.length < 8) {
                return false; // no header
            }

            long realLength = bytesToLong(Arrays.copyOfRange(blob, 0, 8));
            long dataStart = 8;
            long dataEnd = dataStart + realLength;

            if (dataEnd > blob.length) {
                return false; // invalid or corrupted
            }

            byte[] encryptedBytes = Arrays.copyOfRange(blob, (int)dataStart, (int)dataEnd);

            byte[] decryptedBytes = enc.decryptContainer(encryptedBytes, activeKey);

            // Deserialize the manifest
            this.manifest = deserializeManifest(decryptedBytes);
            if (this.manifest == null) {
                // If something's wrong, treat as failed
                return false;
            }

            unlocked = true;
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
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

    public void lockVault() {
        if (!unlocked) {
            System.out.println("Vault is already locked or not yet unlocked.");
            return;
        }
        try {
            // Serialize the manifest
            byte[] serialized = serializeManifest(manifest);

            // Encrypt the container
            byte[] encryptedBytes = enc.encryptContainer(serialized, activeKey);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            // Write the length of the encrypted data as an 8-byte header
            long realLength = encryptedBytes.length;
            bos.write(longToBytes(realLength));

            // Write the actual encrypted container data
            bos.write(encryptedBytes);

            // Calculate final container size in multiples of BLOCK_SIZE
            long currentSize = 8 + realLength; // 8 for header
            long blocksNeeded = (currentSize + BLOCK_SIZE - 1) / BLOCK_SIZE; // integer math rounding up
            long targetSize = blocksNeeded * BLOCK_SIZE; // e.g., 512 MB, 1024 MB, etc.

            long padSize = targetSize - currentSize;
            if (padSize > 0) {
                byte[] padding = new byte[(int) padSize];
                new SecureRandom().nextBytes(padding);
                bos.write(padding);
            }

            byte[] finalBlob = bos.toByteArray();

            // Write container to disk
            try (FileOutputStream fos = new FileOutputStream(vaultPath)) {
                fos.write(finalBlob);
            }

            // Clear memory
            manifest.clear();
            unlocked = false;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] longToBytes(long x) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (DataOutputStream dos = new DataOutputStream(bos)) {
            dos.writeLong(x);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bos.toByteArray();
    }

    public void addFile(String filePath) {
        if (!unlocked) {
            System.out.println("Vault is locked. Unlock first.");
            return;
        }
        try {
            File f = new File(filePath);
            if (!f.exists() || f.isDirectory()) {
                System.out.println("Invalid file path.");
                return;
            }
            String logicalName = f.getName();
            byte[] fileData = Files.readAllBytes(f.toPath());

            // Compute hash
            String hash = computeHash(fileData);

            // Store in manifest
            FileEntry fe = new FileEntry(logicalName, fileData, hash);
            manifest.put(logicalName, fe);

            System.out.println("File added to vault: " + logicalName);
        } catch (IOException | NoSuchElementException e) {
            e.printStackTrace();
        }
    }

    public void removeFile(String logicalName) {
        if (!unlocked) {
            System.out.println("Vault is locked. Unlock first.");
            return;
        }
        if (manifest.containsKey(logicalName)) {
            manifest.remove(logicalName);
            System.out.println("File removed from vault: " + logicalName);
        } else {
            System.out.println("No file found with name: " + logicalName);
        }
    }

    public void extractFile(String logicalName, String destinationPath) {
        if (!unlocked) {
            System.out.println("Vault is locked. Unlock first.");
            return;
        }
        FileEntry fe = manifest.get(logicalName);
        if (fe == null) {
            System.out.println("File not found in vault.");
            return;
        }

        // verify integrity
        String hashNow = computeHash(fe.getData());
        if (!hashNow.equals(fe.getHash())) {
            System.out.println("WARNING: File integrity check failed for " + logicalName);
            return;
        }

        // extract file
        try (FileOutputStream fos = new FileOutputStream(destinationPath)) {
            fos.write(fe.getData());
            System.out.println("File extracted successfully to: " + destinationPath);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // add func to delete file
    }

    public void listFiles() {
        if (!unlocked) {
            System.out.println("Vault is locked. Unlock first.");
            return;
        }
        if (manifest.isEmpty()) {
            System.out.println("Vault is empty.");
            return;
        }
        System.out.println("Files in vault:");
        for (String logicalName : manifest.keySet()) {
            System.out.println(" - " + logicalName);
        }
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

    // serialize manifest to bytes before encrypt
    private byte[] serializeManifest(Map<String, FileEntry> manifest) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(manifest);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    // deserialize manifest bytes after decrypt
    private Map<String, FileEntry> deserializeManifest(byte[] raw) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(raw);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            //noinspection unchecked
            return (Map<String, FileEntry>) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Simple getter
    public boolean isUnlocked() {
        return unlocked;
    }

    // inner class to hold raw data and hash
    private static class FileEntry implements Serializable {
        private final String fileName;
        private final byte[] data;
        private final String hash;

        public FileEntry(String fileName, byte[] data, String hash) {
            this.fileName = fileName;
            this.data = data;
            this.hash = hash;
        }

        public String getFileName() { return fileName; }
        public byte[] getData() { return data; }
        public String getHash() { return hash; }
    }
}
