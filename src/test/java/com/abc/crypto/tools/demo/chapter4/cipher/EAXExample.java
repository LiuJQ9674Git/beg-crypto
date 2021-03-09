package com.abc.crypto.tools.demo.chapter4.cipher;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import java.security.Security;

import static com.abc.crypto.tools.demo.chapter4.cipher.AEADUtils.createConstantKey;
import static com.abc.crypto.tools.demo.chapter4.cipher.AEADUtils.eaxDecrypt;
import static com.abc.crypto.tools.demo.chapter4.cipher.AEADUtils.eaxEncrypt;

/**
 * A simple main for using the EAX methods.
 */
public class EAXExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = createConstantKey();

        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");

        System.out.println("msg  : " + Hex.toHexString(msg));

        byte[] cText = eaxEncrypt(aesKey, iv, msg);

        System.out.println("cText: " + Hex.toHexString(cText));

        byte[] pText = eaxDecrypt(aesKey, iv, cText);

        System.out.println("pText: " + Hex.toHexString(pText));
    }
}
