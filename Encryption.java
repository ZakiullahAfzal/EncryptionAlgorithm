public class Encryption {

    private static final double PI = Math.PI;
    private static final double EPSILON = 0.001;

    private static String encrypt(double valueB, double valueF) {
        if (valueF == 0 || valueB == valueF) {
            double sqrtB = Math.sqrt(valueB);
            double encryptedValue = (sqrtB == (int) sqrtB) ? sqrtB * PI : (sqrtB + EPSILON) * PI;
            return encryptedValue + "-0";
        }

        double encryptedB = calculateEncryptedValue(valueB);
        double encryptedF = calculateEncryptedValue(valueF);

        double med = Math.abs(encryptedB - encryptedF);
        return (encryptedB + encryptedF) + "-" + med;
    }

    private static double calculateEncryptedValue(double value) {
        double temp = Math.sqrt(value) * PI;
        return (Math.pow(Math.sqrt(temp / PI), 2) == value ? temp : temp + EPSILON;
    }

    private static int dCrypt(String value) {
        String[] parts = value.split("-", 2);
        double n = Double.parseDouble(parts[0]);
        
        if (parts[1].equals("0")) {
            return (int) Math.pow(n / PI, 2);
        }

        double m = Double.parseDouble(parts[1]);
        double n1 = (n - m) / 2;
        double m1 = n1 + m;
        
        return (int) (Math.pow(m1 / PI, 2) + (int) Math.pow(n1 / PI, 2);
    }

    public static String divider(String value) {
        int state = Integer.parseInt(value);
        int back = Integer.parseInt(new StringBuilder(value).reverse().toString());
        
        if (state - back <= 0 || back < 10) {
            return encrypt(state, 0);
        }
        return encrypt(back, state - back);
    }

    public static String login(String value, boolean mode) {
        return mode ? String.valueOf(dCrypt(value)) : divider(value);
    }
}
