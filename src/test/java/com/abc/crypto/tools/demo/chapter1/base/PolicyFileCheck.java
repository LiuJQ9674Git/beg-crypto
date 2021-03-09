package com.abc.crypto.tools.demo.chapter1.base;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * A simple application to check for unrestricted policy files.
 */
public class PolicyFileCheck
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws NoSuchAlgorithmException
    {
        try
        {
            Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding", "BC");

            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(new byte[32], "Blowfish"));

            System.out.print("true");
        }
        catch (NoSuchAlgorithmException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            System.out.print("false");
        }
    }
}
