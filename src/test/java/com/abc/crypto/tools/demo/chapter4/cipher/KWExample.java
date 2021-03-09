package com.abc.crypto.tools.demo.chapter4.cipher;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.security.Security;

/**
 * An example of KW style key wrapping - note in this case the input must be
 * aligned on an 8 byte boundary (for AES).
 */
public class KWExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = AEADUtils.createConstantKey();

        SecretKeySpec keyToWrap = new SecretKeySpec(
            Hex.decode("00010203040506070706050403020100"), "Blowfish");

        // wrap the key
        Cipher wrapCipher = Cipher.getInstance("AESKW", "BC");

        wrapCipher.init(Cipher.WRAP_MODE, aesKey);

        byte[] cText = wrapCipher.wrap(keyToWrap);

        // unwrap the key
        Cipher unwrapCipher = Cipher.getInstance("AESKW", "BC");

        unwrapCipher.init(Cipher.UNWRAP_MODE, aesKey);

        SecretKey unwrappedKey =
            (SecretKey)unwrapCipher.unwrap(cText, "Blowfish", Cipher.SECRET_KEY);

        System.out.println("key: " + unwrappedKey.getAlgorithm());
        System.out.println("   : " + Arrays.areEqual(
                                         keyToWrap.getEncoded(),
                                         unwrappedKey.getEncoded()));
    }
}
