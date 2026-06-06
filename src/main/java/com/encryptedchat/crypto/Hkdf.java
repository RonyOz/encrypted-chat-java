package com.encryptedchat.crypto;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

final class Hkdf {
    private static final String HMAC_SHA_256 = "HmacSHA256";
    private static final int HASH_LENGTH = 32;

    private Hkdf() {
    }

    static byte[] extract(byte[] salt, byte[] inputKeyMaterial) throws GeneralSecurityException {
        byte[] actualSalt = salt == null ? new byte[HASH_LENGTH] : salt;
        Mac mac = Mac.getInstance(HMAC_SHA_256);
        mac.init(new SecretKeySpec(actualSalt, HMAC_SHA_256));
        return mac.doFinal(inputKeyMaterial);
    }

    static byte[] expand(byte[] pseudoRandomKey, byte[] info, int length)
            throws GeneralSecurityException {
        if (length < 0 || length > 255 * HASH_LENGTH) {
            throw new IllegalArgumentException("Longitud HKDF invalida: " + length);
        }

        Mac mac = Mac.getInstance(HMAC_SHA_256);
        mac.init(new SecretKeySpec(pseudoRandomKey, HMAC_SHA_256));

        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        int offset = 0;
        int block = 1;

        while (offset < length) {
            mac.reset();
            mac.update(previous);
            if (info != null) {
                mac.update(info);
            }
            mac.update((byte) block);
            byte[] current = mac.doFinal();
            int copied = Math.min(current.length, length - offset);
            System.arraycopy(current, 0, output, offset, copied);
            offset += copied;
            Arrays.fill(previous, (byte) 0);
            previous = current;
            block++;
        }

        Arrays.fill(previous, (byte) 0);
        return output;
    }
}

