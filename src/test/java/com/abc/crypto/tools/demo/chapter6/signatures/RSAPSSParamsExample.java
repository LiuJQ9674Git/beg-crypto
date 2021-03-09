package com.abc.crypto.tools.demo.chapter6.signatures;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import static com.abc.crypto.tools.demo.chapter6.signatures.RsaUtils.generateRSAPSSSignature;
import static com.abc.crypto.tools.demo.chapter6.signatures.RsaUtils.verifyRSAPSSSignature;

/**
 * An example of using RSA PSS with a PSSParameterSpec based on SHA-256.
 */
public class RSAPSSParamsExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        KeyPair rsaKp = RsaUtils.generateRSAKeyPair();
        PSSParameterSpec pssSpec = new PSSParameterSpec(
            "SHA-256",
            "MGF1", new MGF1ParameterSpec("SHA-256"), 32,
            1);

        byte[] pssSignature = RsaUtils.generateRSAPSSSignature(
            rsaKp.getPrivate(), pssSpec, Strings.toByteArray("hello, world!"));

        System.out.println("RSA PSS verified: "
                                + RsaUtils.verifyRSAPSSSignature(
                                        rsaKp.getPublic(), pssSpec,
                                        Strings.toByteArray("hello, world!"),
                                        pssSignature));


        pssSignature = RsaUtils.generatePKCS1dot5Signature(
                rsaKp.getPrivate(), Strings.toByteArray("hello, world!"));

        System.out.println("SHA256withRSA verified: "
                + RsaUtils.verifyPKCS1dot5Signature(
                rsaKp.getPublic(),
                Strings.toByteArray("hello, world!"),
                pssSignature));

        pssSignature = RsaUtils.generateRSAPSSSignature(
                rsaKp.getPrivate(), Strings.toByteArray("hello, world!"));

        System.out.println("SHA256withRSAandMGF1 verified: "
                + RsaUtils.verifyRSAPSSSignature(
                rsaKp.getPublic(),
                Strings.toByteArray("hello, world!"),
                pssSignature));

        pssSignature = RsaUtils.generateRSAPSSSignature(
                rsaKp.getPrivate(), Strings.toByteArray("hello, world!"));


    }
}
