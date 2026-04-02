import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        String encrypted1 = Encryption.encrypt("Hello", 1);
        String encrypted2 = Encryption.encrypt("Hello", 2);
        String encrypted3 = Encryption.encrypt("Hello", 3);

        System.out.println(encrypted1);
        System.out.println(encrypted2);
        System.out.println(encrypted3);

        System.out.println(Encryption.decrypt(encrypted1, 1));
        System.out.println(Encryption.decrypt(encrypted2, 2));
        System.out.println(Encryption.decrypt(encrypted3, 3));
    }
}
