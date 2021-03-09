package com.abc.crypto.tools.demo.chapter4.cipher;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * A simple GCM example without Additional Associated Data (AAD)
 */
public class GCMExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = AEADUtils.createConstantKey();

        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");

        System.out.println("msg  : " + Hex.toHexString(msg));

        byte[] cText = AEADUtils.gcmEncrypt(aesKey, iv, 128, msg);

        System.out.println("cText: " + Hex.toHexString(cText));

        byte[] pText = AEADUtils.gcmDecrypt(aesKey, iv, 128, cText);

        System.out.println("pText: " + Hex.toHexString(pText));
    }
}
