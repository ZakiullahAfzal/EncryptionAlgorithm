import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Encryption {

    public static String encrypt(String text, int mode) {
        switch (mode) {
            case 1:
                EncryptionMathCipher.resetKey();
                StringBuilder encrypted = new StringBuilder();
                for (char ch : text.toCharArray()) {
                    encrypted.append(EncryptionMathCipher.divider((int) ch));
                }
                return EncryptionMathCipher.cleanEncrypted(encrypted.toString());

            case 2:
                return EncryptionHexCipher.encryptText(text);

            case 3:
                return EncryptionCompactCipher.encryptText(text);

            default:
                throw new IllegalArgumentException("Invalid mode");
        }
    }

    public static String decrypt(String text, int mode, String key) {
        switch (mode) {
            case 1:
                return EncryptionMathCipher.login(text, key);

            case 2:
                return EncryptionHexCipher.decryptText(text);

            case 3:
                return EncryptionCompactCipher.decryptText(text);

            default:
                throw new IllegalArgumentException("Invalid mode");
        }
    }

    public static String getMathKey() {
        return EncryptionMathCipher.getKey();
    }

    public static void printHexKeys() {
        EncryptionHexCipher.printKeys();
    }

    private static class EncryptionCompactCipher {

        private static final int KEY1 = 17;
        private static final int KEY2 = 43;
        private static final int MASK = 91;

        private static final char[] ALPHABET =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

        private static final int[] REVERSE = new int[128];

        static {
            for (int i = 0; i < REVERSE.length; i++) {
                REVERSE[i] = -1;
            }
            for (int i = 0; i < ALPHABET.length; i++) {
                REVERSE[ALPHABET[i]] = i;
            }
        }

        private static int encryptChar(int value, int position) {
            return (value + KEY1 + (position * KEY2)) ^ MASK;
        }

        private static int decryptChar(int value, int position) {
            return (value ^ MASK) - KEY1 - (position * KEY2);
        }

        public static String encryptText(String text) {
            if (text == null || text.isEmpty()) {
                return "";
            }

            byte[] bytes = new byte[text.length() * 2];

            for (int i = 0; i < text.length(); i++) {
                int encrypted = encryptChar(text.charAt(i), i);
                bytes[i * 2] = (byte) ((encrypted >> 8) & 0xFF);
                bytes[i * 2 + 1] = (byte) (encrypted & 0xFF);
            }

            return encodeCustomBase64(bytes);
        }

        public static String decryptText(String encodedText) {
            if (encodedText == null || encodedText.isEmpty()) {
                return "";
            }

            byte[] bytes = decodeCustomBase64(encodedText);

            if (bytes.length % 2 != 0) {
                throw new IllegalArgumentException("Invalid encrypted data length.");
            }

            StringBuilder result = new StringBuilder(bytes.length / 2);

            for (int i = 0; i < bytes.length; i += 2) {
                int encrypted = ((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF);
                int position = i / 2;
                int decrypted = decryptChar(encrypted, position);
                result.append((char) decrypted);
            }

            return result.toString();
        }

        private static String encodeCustomBase64(byte[] data) {
            StringBuilder result = new StringBuilder((data.length * 4 + 2) / 3);

            int i = 0;
            while (i < data.length) {
                int b1 = data[i++] & 0xFF;
                int b2 = (i < data.length) ? data[i++] & 0xFF : 0;
                int b3 = (i < data.length) ? data[i++] & 0xFF : 0;

                int combined = (b1 << 16) | (b2 << 8) | b3;

                result.append(ALPHABET[(combined >> 18) & 0x3F]);
                result.append(ALPHABET[(combined >> 12) & 0x3F]);

                if (i - 1 < data.length) {
                    result.append(ALPHABET[(combined >> 6) & 0x3F]);
                }
                if (i < data.length + 1) {
                    result.append(ALPHABET[combined & 0x3F]);
                }
            }

            int mod = data.length % 3;
            if (mod == 1) {
                result.setLength(result.length() - 2);
            } else if (mod == 2) {
                result.setLength(result.length() - 1);
            }

            return result.toString();
        }

        private static byte[] decodeCustomBase64(String text) {
            int len = text.length();

            if (len == 0) {
                return new byte[0];
            }

            int remainder = len % 4;
            int outputLength = (len / 4) * 3;

            if (remainder == 2) {
                outputLength += 1;
            } else if (remainder == 3) {
                outputLength += 2;
            } else if (remainder != 0) {
                throw new IllegalArgumentException("Invalid encoded text length.");
            }

            byte[] output = new byte[outputLength];

            int in = 0;
            int out = 0;

            while (in < len) {
                int c1 = REVERSE[text.charAt(in++)];
                int c2 = REVERSE[text.charAt(in++)];
                int c3 = (in < len) ? REVERSE[text.charAt(in++)] : 0;
                int c4 = (in < len) ? REVERSE[text.charAt(in++)] : 0;

                if (c1 < 0 || c2 < 0 || c3 < 0 || c4 < 0) {
                    throw new IllegalArgumentException("Invalid character in encoded text.");
                }

                int combined = (c1 << 18) | (c2 << 12) | (c3 << 6) | c4;

                if (out < outputLength) {
                    output[out++] = (byte) ((combined >> 16) & 0xFF);
                }
                if (out < outputLength) {
                    output[out++] = (byte) ((combined >> 8) & 0xFF);
                }
                if (out < outputLength) {
                    output[out++] = (byte) (combined & 0xFF);
                }
            }

            return output;
        }
    }

    private static class EncryptionHexCipher {

        private static final int KEY1;
        private static final int KEY2;
        private static final int MASK;

        static {
            try {
                SecureRandom random = SecureRandom.getInstanceStrong();
                KEY1 = random.nextInt(29) + 1;
                KEY2 = random.nextInt(29) + 1;
                MASK = random.nextInt(99) + 1;
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        public static void printKeys() {
            System.out.println("KEY1 = " + KEY1);
            System.out.println("KEY2 = " + KEY2);
            System.out.println("MASK = " + MASK);
        }

        private static int encryptChar(int value, int position) {
            return (value + KEY1 + (position * KEY2)) ^ MASK;
        }

        private static int decryptChar(int value, int position) {
            return (value ^ MASK) - KEY1 - (position * KEY2);
        }

        public static String divider(String value, int position) {
            int state = Integer.parseInt(value);
            int encrypted = encryptChar(state, position);
            return Integer.toHexString(encrypted).toUpperCase();
        }

        public static String login(String value, boolean mode, int position) {
            if (mode) {
                int encrypted = Integer.parseInt(value, 16);
                return String.valueOf(decryptChar(encrypted, position));
            } else {
                return divider(value, position);
            }
        }

        public static String encryptText(String text) {
            StringBuilder result = new StringBuilder();

            for (int i = 0; i < text.length(); i++) {
                result.append(login(String.valueOf((int) text.charAt(i)), false, i));
                if (i < text.length() - 1) {
                    result.append("-");
                }
            }

            return result.toString();
        }

        public static String decryptText(String encryptedText) {
            String[] parts = encryptedText.split("-");
            StringBuilder result = new StringBuilder();

            for (int i = 0; i < parts.length; i++) {
                result.append((char) Integer.parseInt(login(parts[i], true, i)));
            }

            return result.toString();
        }
    }

    private static class EncryptionMathCipher {

        private static final double PI = Math.PI;
        private static final double EPS = 0.001;
        private static final StringBuilder rawKey = new StringBuilder();
        private static int indexCounter = 0;

        private static double encodeValue(double value) {
            double root = Math.sqrt(value);
            double encoded = root * PI;
            double restored = Math.pow(Math.sqrt(encoded / PI), 2);

            if (Math.abs(restored - value) > 1e-9) {
                encoded += EPS;
            }

            return encoded;
        }

        private static String encrypt(double valueB, double valueF) {
            if (valueF == 0 || valueB == valueF) {
                double root = Math.sqrt(valueB);
                double encoded = (root == (int) root) ? (root * PI) : ((root + EPS) * PI);

                rawKey.append(indexCounter).append(":0").append("_");
                indexCounter++;
                return encoded + "_";
            }

            valueB = encodeValue(valueB);
            valueF = encodeValue(valueF);

            double med = Math.abs(valueB - valueF);
            rawKey.append(indexCounter).append(":").append(med).append("_");
            indexCounter++;

            return (valueB + valueF) + "_";
        }

        private static int dCrypt(double sum, double med) {
            if (med == 0) {
                return (int) Math.pow(sum / PI, 2);
            }

            double n = (sum - med) / 2;
            double m = (sum + med) / 2;

            n = Math.pow(n / PI, 2);
            m = Math.pow(m / PI, 2);

            return (int) (n + m);
        }

        private static int reverseNumber(int number) {
            return Integer.parseInt(new StringBuilder(String.valueOf(number)).reverse().toString());
        }

        public static String divider(int value) {
            int back = reverseNumber(value);

            if (value <= back || back < 10) {
                return encrypt(value, 0);
            }

            return encrypt(back, value - back);
        }

        public static String login(String encryptedText, String keyText) {
            String[] encryptedParts = encryptedText.isEmpty() ? new String[0] : encryptedText.split("_");
            String[] keyParts = keyText.isEmpty() ? new String[0] : keyText.split("_");

            double[] meds = new double[encryptedParts.length];

            for (String keyPart : keyParts) {
                if (keyPart.isEmpty()) continue;

                String[] pair = keyPart.split(":");
                int position = Integer.parseInt(pair[0]);
                double med = Double.parseDouble(pair[1]);

                if (position >= 0 && position < meds.length) {
                    meds[position] = med;
                }
            }

            StringBuilder result = new StringBuilder();

            for (int i = 0; i < encryptedParts.length; i++) {
                if (encryptedParts[i].isEmpty()) continue;

                double sum = Double.parseDouble(encryptedParts[i]);
                result.append((char) dCrypt(sum, meds[i]));
            }

            return result.toString();
        }

        public static void resetKey() {
            rawKey.setLength(0);
            indexCounter = 0;
        }

        public static String getKey() {
            String raw = rawKey.toString();

            if (raw.endsWith("_")) {
                raw = raw.substring(0, raw.length() - 1);
            }

            if (raw.isEmpty()) {
                return "";
            }

            String[] parts = raw.split("_");
            StringBuilder cleaned = new StringBuilder();

            for (String part : parts) {
                if (part.isEmpty()) continue;

                String[] pair = part.split(":");
                double med = Double.parseDouble(pair[1]);

                if (med != 0) {
                    if (cleaned.length() > 0) {
                        cleaned.append("_");
                    }
                    cleaned.append(part);
                }
            }

            return cleaned.toString();
        }

        public static String cleanEncrypted(String encryptedText) {
            if (encryptedText.endsWith("_")) {
                return encryptedText.substring(0, encryptedText.length() - 1);
            }
            return encryptedText;
        }
    }

}
