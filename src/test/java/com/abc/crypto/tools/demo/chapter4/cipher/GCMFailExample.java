package com.abc.crypto.tools.demo.chapter4.cipher;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import java.security.Security;

/**
 * A simple GCM example that shows data corruption.
 */
public class GCMFailExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = AEADUtils.createConstantKey();

        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");

        byte[] cText = AEADUtils.gcmEncrypt(aesKey, iv, 128, msg);

        // tamper with the cipher text
        cText[0] = (byte)~cText[0];

        byte[] pText = AEADUtils.gcmDecrypt(aesKey, iv, 128, cText);
    }
}
