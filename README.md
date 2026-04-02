
Ecryptin Algorithms:

First Math Base:
This is a simple encryption algorithm for practice, based on a mathematical concept. For example, if we take the character "a," it is first converted to its ASCII code (97), and then the digits are reversed to get 79.  | 97-79=18  n = (sqrt(79)*PI - sqrt(18)*PI)
m = (sqrt(79)*PI + sqrt(18)*PI for decryption m = (m-n) / 2 | a = m+n | (m/PI)^2 (a/PI)^2 | b = (a+m) rever(b)   
Note: For any number, such as 101, we simply calculate the square root of the number and then multiply it by PI. 


Second  Keys Base --------------------------------------------------------------------------------------------------------------------------

This project implements a simple custom encryption algorithm based on integer transformation, character position, and bitwise XOR.

Each input character is converted into its ASCII value and encrypted using three secret constants:

encrypted = (value + KEY1 + (position * KEY2)) ^ MASK

To decrypt:

value = (encrypted ^ MASK) - KEY1 - (position * KEY2)

KEY1 provides a fixed shift, KEY2 adds position-based variation, and MASK applies bit-level scrambling using XOR.

The encrypted output is stored as hexadecimal values separated by dashes, for example:

4F-8A-91-BC

Because character position is included in the formula, repeated characters may produce different encrypted values at different positions.

Note: The same KEY1, KEY2, and MASK values must be used for both encryption and decryption.


Third encoding -----------------------------------------------------------------------------------------------------------------------------------------


This project implements a custom encryption algorithm that transforms characters into a compact encoded string without visible separators.

Each character is converted into its ASCII value and encrypted using:

encrypted = (value + KEY1 + (position * KEY2)) ^ MASK

To decrypt:

value = (encrypted ^ MASK) - KEY1 - (position * KEY2)

After encryption, each result is stored in 2 bytes, and all bytes are encoded using a custom Base64-style alphabet:

ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/

This produces a compact encrypted string such as:

AikDUARpBKg

Compared with the previous version, this approach removes long numeric outputs and separators, making the encrypted text cleaner and more compact.

Note: The same KEY1, KEY2, and MASK values are required for correct decryption.
