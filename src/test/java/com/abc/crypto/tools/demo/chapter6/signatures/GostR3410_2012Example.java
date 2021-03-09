package com.abc.crypto.tools.demo.chapter6.signatures;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

/**
 * An example of using GOST R 34.10-2012 to sign data and then
 * verifying the resulting signature.
 */
public class GostR3410_2012Example
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        KeyPair ecKp = GostR3410_2012Utils.generateGOST3410_2012KeyPair(
                            "Tc26-Gost-3410-12-512-paramSetA");

        byte[] ecGostSig = GostR3410_2012Utils.generateGOST3410_2012Signature(
            ecKp.getPrivate(), Strings.toByteArray("hello, world!"),
            "ECGOST3410-2012-512");

        System.err.println("ECGOST3410-2012-512 verified: " +
                    GostR3410_2012Utils.verifyGOST3410_2012Signature(
                        ecKp.getPublic(), Strings.toByteArray("hello, world!"),
                        "ECGOST3410-2012-512", ecGostSig));
    }
}
