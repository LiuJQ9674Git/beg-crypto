package com.abc.crypto.tools.demo.chapter6.signatures;

import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import static com.abc.signature.DsaUtils.generateDSAKeyPair;
import static com.abc.signature.DsaUtils.generateDSASignature;
import static com.abc.signature.DsaUtils.verifyDSASignature;

public class DsaExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws Exception
    {
        byte[] msg = Strings.toByteArray("hello, world!");

        Security.addProvider(new BouncyCastleProvider());
        KeyPair dsaKp = generateDSAKeyPair();

        byte[] dsaSignature = generateDSASignature(dsaKp.getPrivate(), msg);

        System.out.println("DSA verified: " + verifyDSASignature(dsaKp.getPublic(), msg, dsaSignature));
    }
}
