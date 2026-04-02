

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class Encryption {


    /**
     *  @program Encryption 
     */

private static class Encryption {

    // Custom secret values used in the cipher
    // KEY1 = fixed shift
    // KEY2 = position-based shift
    // MASK = XOR mask
    private static final int KEY1 = 17;
    private static final int KEY2 = 43;
    private static final int MASK = 91;

    // Custom alphabet used to convert bytes into readable text
    // Similar to Base64 alphabet
    private static final char[] ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    // Reverse lookup table:
    // given a character like 'A', 'b', '7', '+', '/'
    // find its numeric index in ALPHABET
    private static final int[] REVERSE = new int[128];

    static {
        // Initialize all values as invalid
        for (int i = 0; i < REVERSE.length; i++) {
            REVERSE[i] = -1;
        }

        // Fill reverse mapping
        // Example: REVERSE['A'] = 0, REVERSE['B'] = 1, ...
        for (int i = 0; i < ALPHABET.length; i++) {
            REVERSE[ALPHABET[i]] = i;
        }
    }

    // Encrypt one character code using:
    // 1. fixed shift
    // 2. position-based shift
    // 3. XOR mask
    private static int encryptChar(int value, int position) {
        return (value + KEY1 + (position * KEY2)) ^ MASK;
    }

    // Reverse the encryption process
    private static int decryptChar(int value, int position) {
        return (value ^ MASK) - KEY1 - (position * KEY2);
    }

    // Encrypt the whole text
    public static String encryptText(String text) {
        // If text is null or empty, return empty string
        if (text == null || text.isEmpty()) {
            return "";
        }

        // Each encrypted character is stored in 2 bytes
        // So total byte array length = text length * 2
        byte[] bytes = new byte[text.length() * 2];

        for (int i = 0; i < text.length(); i++) {
            int encrypted = encryptChar(text.charAt(i), i);

            // Split encrypted integer into 2 bytes
            // High byte goes first
            bytes[i * 2] = (byte) ((encrypted >> 8) & 0xFF);

            // Low byte goes second
            bytes[i * 2 + 1] = (byte) (encrypted & 0xFF);
        }

        // Convert byte array into readable encoded text
        return encodeCustomBase64(bytes);
    }

    // Decrypt the encoded text back to the original plain text
    public static String decryptText(String encodedText) {
        // Empty input gives empty result
        if (encodedText == null || encodedText.isEmpty()) {
            return "";
        }

        // Convert encoded text back into raw bytes
        byte[] bytes = decodeCustomBase64(encodedText);

        // Each encrypted character must occupy 2 bytes
        if (bytes.length % 2 != 0) {
            throw new IllegalArgumentException("Invalid encrypted data length.");
        }

        // Result will contain one character for every 2 bytes
        StringBuilder result = new StringBuilder(bytes.length / 2);

        for (int i = 0; i < bytes.length; i += 2) {
            // Rebuild the encrypted integer from 2 bytes
            int encrypted = ((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF);

            // Original character position
            int position = i / 2;

            // Decrypt integer back to original character code
            int decrypted = decryptChar(encrypted, position);

            // Convert integer back to char
            result.append((char) decrypted);
        }

        return result.toString();
    }

    // Encode raw bytes into readable text using custom alphabet
    private static String encodeCustomBase64(byte[] data) {
        // Rough size estimate for efficiency
        StringBuilder result = new StringBuilder((data.length * 4 + 2) / 3);

        int i = 0;
        while (i < data.length) {
            // Read up to 3 bytes
            int b1 = data[i++] & 0xFF;
            int b2 = (i < data.length) ? data[i++] & 0xFF : 0;
            int b3 = (i < data.length) ? data[i++] & 0xFF : 0;

            // Merge them into one 24-bit integer
            int combined = (b1 << 16) | (b2 << 8) | b3;

            // Split 24 bits into four 6-bit parts
            result.append(ALPHABET[(combined >> 18) & 0x3F]);
            result.append(ALPHABET[(combined >> 12) & 0x3F]);

            // Add third encoded char if enough data exists
            if (i - 1 < data.length) {
                result.append(ALPHABET[(combined >> 6) & 0x3F]);
            }

            // Add fourth encoded char if enough data exists
            if (i < data.length + 1) {
                result.append(ALPHABET[combined & 0x3F]);
            }
        }

        // Remove extra characters caused by missing bytes at the end
        int mod = data.length % 3;
        if (mod == 1) {
            result.setLength(result.length() - 2);
        } else if (mod == 2) {
            result.setLength(result.length() - 1);
        }

        return result.toString();
    }

    // Decode encoded text back into raw bytes
    private static byte[] decodeCustomBase64(String text) {
        int len = text.length();

        if (len == 0) {
            return new byte[0];
        }

        // Calculate output byte array size based on encoded text length
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
            // Read up to 4 encoded characters
            int c1 = REVERSE[text.charAt(in++)];
            int c2 = REVERSE[text.charAt(in++)];
            int c3 = (in < len) ? REVERSE[text.charAt(in++)] : 0;
            int c4 = (in < len) ? REVERSE[text.charAt(in++)] : 0;

            // Validate characters
            if (c1 < 0 || c2 < 0 || c3 < 0 || c4 < 0) {
                throw new IllegalArgumentException("Invalid character in encoded text.");
            }

            // Merge four 6-bit values into one 24-bit integer
            int combined = (c1 << 18) | (c2 << 12) | (c3 << 6) | c4;

            // Split back into original bytes
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

    // Same style as your old code:
    // mode = false -> encrypt
    // mode = true  -> decrypt
    public static String login(String value, boolean mode) {
        return mode ? decryptText(value) : encryptText(value);
    }
}


    



    //============================================================================================

private static class EncryptionBsedOnKeys{

    // Three secret values used in the custom cipher
    // KEY1 = fixed shift
    // KEY2 = position-based shift
    // MASK = XOR mask for bit-level scrambling
    private static final int KEY1;
    private static final int KEY2;
    private static final int MASK;

    // Static block runs once when the class is loaded
    // It generates random values for the three cipher constants
    static {
        try {
            // Random fixed shift from 1 to 29
            KEY1 = SecureRandom.getInstanceStrong().nextInt(29) + 1;

            // Random position multiplier from 1 to 29
            KEY2 = SecureRandom.getInstanceStrong().nextInt(29) + 1;

            // Random XOR mask from 1 to 99
            MASK = SecureRandom.getInstanceStrong().nextInt(99) + 1;

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Prints the generated secret values
    // Useful for testing and understanding how encryption changes
    public static void printKeys() {
        System.out.println("KEY1 = " + KEY1);
        System.out.println("KEY2 = " + KEY2);
        System.out.println("MASK = " + MASK);
    }

    // Encrypts one character code using:
    // 1. fixed shift (KEY1)
    // 2. position-based shift (position * KEY2)
    // 3. XOR mask (MASK)
    private static int encryptChar(int value, int position) {
        return (value + KEY1 + (position * KEY2)) ^ MASK;
    }

    // Reverses the encryption process:
    // 1. remove XOR mask
    // 2. subtract fixed shift
    // 3. subtract position-based shift
    private static int decryptChar(int value, int position) {
        return (value ^ MASK) - KEY1 - (position * KEY2);
    }

    // Converts one input character code into encrypted hex text
    // Example: 244 -> "F4"
    public static String divider(String value, int position) {
        int state = Integer.parseInt(value);
        int encrypted = encryptChar(state, position);
        return Integer.toHexString(encrypted).toUpperCase();
    }

    // Works like your old login style:
    // mode = false -> encrypt
    // mode = true  -> decrypt
    public static String login(String value, boolean mode, int position) {
        if (mode) {
            // Convert hex text back to integer, then decrypt
            int encrypted = Integer.parseInt(value, 16);
            return String.valueOf(decryptChar(encrypted, position));
        } else {
            // Encrypt integer text to hex
            return divider(value, position);
        }
    }

    // Encrypts the full text character by character
    // Each encrypted token is separated by "-"
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

    // Decrypts the full encrypted text
    // Splits the encrypted string by "-"
    // Then decrypts each token using its position
    public static String decryptText(String encryptedText) {
        String[] parts = encryptedText.split("-");
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < parts.length; i++) {
            result.append((char) Integer.parseInt(login(parts[i], true, i)));
        }

        return result.toString();
    }
}



    //=================================================================================================
   private static class EncryptionBasedOnPI{

    // Mathematical constants used in the custom encoding logic
    private static final double PI = Math.PI;
    private static final double EPS = 0.001;

    // Stores key information in the form: index:med_index:med_...
    // Example: 1:14.5_4:8.2
    private static final StringBuilder rawKey = new StringBuilder();

    // Tracks the position of each character during encryption
    private static int indexCounter = 0;

    // Encodes a single numeric value using sqrt and PI
    private static double encodeValue(double value) {
        double root = Math.sqrt(value);
        double encoded = root * PI;

        // Try to restore the original value to check if precision was lost
        double restored = Math.pow(Math.sqrt(encoded / PI), 2);

        // If precision changed, add a very small correction value
        if (Math.abs(restored - value) > 1e-9) {
            encoded += EPS;
        }

        return encoded;
    }

    // Encrypts two values and returns the encrypted text part
    // Also stores med information inside rawKey
    private static String encrypt(double valueB, double valueF) {

        // Case 1: no second value exists
        if (valueF == 0 || valueB == valueF) {
            double root = Math.sqrt(valueB);

            // If sqrt is integer, encode directly
            // Otherwise add EPS before multiplying by PI
            double encoded = (root == (int) root) ? (root * PI) : ((root + EPS) * PI);

            // Store index with med = 0 in key
            rawKey.append(indexCounter).append(":0").append("_");
            indexCounter++;

            // Return encrypted piece followed by separator
            return encoded + "_";
        }

        // Case 2: both values are encoded separately
        valueB = encodeValue(valueB);
        valueF = encodeValue(valueF);

        // med = absolute difference between the two encoded values
        double med = Math.abs(valueB - valueF);

        // Store only the position and med in key
        rawKey.append(indexCounter).append(":").append(med).append("_");
        indexCounter++;

        // Return encrypted piece as sum of both encoded values
        return (valueB + valueF) + "_";
    }

    // Decrypts one encrypted numeric token using its sum and med
    private static int dCrypt(double sum, double med) {

        // If med is 0, this was a simple encoded value
        if (med == 0) {
            return (int) Math.pow(sum / PI, 2);
        }

        // Reconstruct the two original encoded values
        double n = (sum - med) / 2;
        double m = (sum + med) / 2;

        // Reverse the encoding process
        n = Math.pow(n / PI, 2);
        m = Math.pow(m / PI, 2);

        // Return the original integer character code
        return (int) (n + m);
    }

    // Reverses digits of a number
    // Example: 123 -> 321
    private static int reverseNumber(int number) {
        return Integer.parseInt(new StringBuilder(String.valueOf(number)).reverse().toString());
    }

    // Splits the integer code into two parts before encryption
    public static String divider(int value) {
        int back = reverseNumber(value);

        // If reversed number is bigger, equal, or too small,
        // use simple encryption path
        if (value <= back || back < 10) {
            return encrypt(value, 0);
        }

        // Otherwise split into:
        // back
        // value - back
        return encrypt(back, value - back);
    }

    // Decrypts the full encrypted text using the encrypted string + key string
    public static String login(String encryptedText, String keyText) {

        // Split encrypted text into parts
        String[] encryptedParts = encryptedText.isEmpty() ? new String[0] : encryptedText.split("_");

        // Split key into parts
        String[] keyParts = keyText.isEmpty() ? new String[0] : keyText.split("_");

        // Each encrypted token will use one med value
        // By default med is 0 unless specified in key
        double[] meds = new double[encryptedParts.length];

        // Read key parts like "2:14.3"
        for (String keyPart : keyParts) {
            if (keyPart.isEmpty()) continue;

            String[] pair = keyPart.split(":");
            int position = Integer.parseInt(pair[0]);
            double med = Double.parseDouble(pair[1]);

            // Put med in the correct character position
            if (position >= 0 && position < meds.length) {
                meds[position] = med;
            }
        }

        StringBuilder result = new StringBuilder();

        // Decrypt each encrypted token
        for (int i = 0; i < encryptedParts.length; i++) {
            if (encryptedParts[i].isEmpty()) continue;

            double sum = Double.parseDouble(encryptedParts[i]);
            result.append((char) dCrypt(sum, meds[i]));
        }

        return result.toString();
    }

    // Clears old key data before a new encryption operation
    public static void resetKey() {
        rawKey.setLength(0);
        indexCounter = 0;
    }

    // Returns the cleaned key without trailing separator
    // Also removes entries where med == 0
    public static String getKey() {
        String raw = rawKey.toString();

        // Remove last "_"
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

            // Keep only non-zero med entries
            if (med != 0) {
                if (cleaned.length() > 0) {
                    cleaned.append("_");
                }
                cleaned.append(part);
            }
        }

        return cleaned.toString();
    }

    // Removes last "_" from encrypted text
    public static String cleanEncrypted(String encryptedText) {
        if (encryptedText.endsWith("_")) {
            return encryptedText.substring(0, encryptedText.length() - 1);
        }
        return encryptedText;
    }
}
    
}




