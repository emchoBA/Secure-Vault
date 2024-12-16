import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        String vaultPath = "D:\\vault.sec";
        String metaPath = "D:\\vault.meta";   // hashed pass, salt

        Scanner sc = new Scanner(System.in);
        Vault vault = new Vault(vaultPath, metaPath);

        while (true) {
            System.out.println("\n--- Secure File Vault ---");
            System.out.println("1. Create new vault");
            System.out.println("2. Unlock vault");
            System.out.println("3. Add file");
            System.out.println("4. Remove file");
            System.out.println("5. Extract file");
            System.out.println("6. View files in vault");
            System.out.println("7. Lock vault");
            System.out.println("8. Exit");
            System.out.print("Select an option: ");

            int choice;
            try {
                choice = Integer.parseInt(sc.nextLine());
            } catch (NumberFormatException e) {
                System.out.println("Invalid input, try again.");
                continue;
            }

            switch (choice) {
                case 1:
                    System.out.print("Enter vault password: ");
                    String newPass = sc.nextLine();
                    vault.createVault(newPass);
                    System.out.println("Vault created and locked.");
                    break;
                case 2:
                    System.out.print("Enter vault password: ");
                    String unlockPass = sc.nextLine();
                    if (vault.unlockVault(unlockPass)) {
                        System.out.println("Vault unlocked successfully.");
                    } else {
                        System.out.println("Invalid password or vault metadata missing.");
                    }
                    break;
                case 3:
                    if (!vault.isUnlocked()) {
                        System.out.println("Vault is locked. Unlock first.");
                        break;
                    }
                    System.out.print("Enter file path to add: ");
                    String pathToAdd = sc.nextLine();
                    vault.addFile(pathToAdd);
                    break;
                case 4:
                    if (!vault.isUnlocked()) {
                        System.out.println("Vault is locked. Unlock first.");
                        break;
                    }
                    System.out.print("Enter filename to remove (logical name in vault): ");
                    String removeName = sc.nextLine();
                    vault.removeFile(removeName);
                    break;
                case 5:
                    if (!vault.isUnlocked()) {
                        System.out.println("Vault is locked. Unlock first.");
                        break;
                    }
                    System.out.print("Enter file name to extract: ");
                    String extractName = sc.nextLine();
                    System.out.print("Enter destination path for extracted file: ");
                    String destPath = sc.nextLine();
                    vault.extractFile(extractName, destPath);
                    break;
                case 6:
                    if (!vault.isUnlocked()) {
                        System.out.println("Vault is locked. Unlock first.");
                        break;
                    }
                    vault.listFiles();
                    break;
                case 7:
                    vault.lockVault();
                    System.out.println("Vault locked.");
                    break;
                case 8:
                    System.out.println("Exiting...");
                    sc.close();
                    return;
                default:
                    System.out.println("Invalid option. Try again.");
            }
        }
    }
}
