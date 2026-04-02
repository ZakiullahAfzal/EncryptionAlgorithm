import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter text: ");
        String input = scanner.nextLine();

        System.out.print("Choose mode (1=Math, 2=Hex, 3=Compact): ");
        int mode = scanner.nextInt();
        scanner.nextLine();

        String encrypted = Encryption.encrypt(input, mode);
        System.out.println("Encrypted: " + encrypted);

        if (mode == 1) {
            String key = Encryption.getMathKey();
            System.out.println("Key: " + key);
            System.out.println("Decrypted: " + Encryption.decrypt(encrypted, mode, key));
        } else {
            System.out.println("Decrypted: " + Encryption.decrypt(encrypted, mode, ""));
        }

        if (mode == 2) {
            Encryption.printHexKeys();
        }
    }
}
