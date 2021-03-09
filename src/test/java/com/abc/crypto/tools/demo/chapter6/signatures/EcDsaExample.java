package com.abc.crypto.tools.demo.chapter6.signatures;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;

import com.abc.signature.EcDsaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import static com.abc.signature.EcDsaUtils.generateECKeyPair;

/**
 * Simple example of the use of the ECDSA methods for signature generation.
 */
public class EcDsaExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        KeyPair ecKp = EcDsaUtils.generateECKeyPair();

        byte[] ecdsaSignature = EcDsaUtils.generateECDSASignature(ecKp.getPrivate(),
                Strings.toByteArray("hello, world!"));

        System.out.println("DSA verified: " + EcDsaUtils.verifyECDSASignature(
            ecKp.getPublic(), Strings.toByteArray("hello, world!"), ecdsaSignature));
    }
}
