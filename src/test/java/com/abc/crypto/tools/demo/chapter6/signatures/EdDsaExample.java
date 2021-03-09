package com.abc.crypto.tools.demo.chapter6.signatures;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import static com.abc.crypto.tools.demo.chapter6.signatures.EdDsaUtils.generateEdDSASignature;
import static com.abc.crypto.tools.demo.chapter6.signatures.EdDsaUtils.generateEd448KeyPair;
import static com.abc.crypto.tools.demo.chapter6.signatures.EdDsaUtils.verifyEdDSASignature;

/**
 * Simple example of the use of the EdDSA methods for Ed448.
 */
public class EdDsaExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        KeyPair ecKp = generateEd448KeyPair();

        byte[] ecdsaSignature = generateEdDSASignature(ecKp.getPrivate(),
                Strings.toByteArray("hello, world!"));

        System.out.println("EdDSA verified: " + verifyEdDSASignature(
            ecKp.getPublic(), Strings.toByteArray("hello, world!"), ecdsaSignature));
    }
}
