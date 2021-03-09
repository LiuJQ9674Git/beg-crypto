package com.abc.crypto.tools.demo.chapter6.signatures;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import static com.abc.crypto.tools.demo.chapter6.signatures.EcDsaUtils.generateECKeyPair;
import static com.abc.crypto.tools.demo.chapter6.signatures.SM2Utils.generateSM2Signature;
import static com.abc.crypto.tools.demo.chapter6.signatures.SM2Utils.verifySM2Signature;

/**
 * An example of using SM2 with an SM2ParameterSpec to specify the ID string
 * for the signature.
 */
public class SM2ParamSpecExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        KeyPair ecKp = EcDsaUtils.generateECKeyPair("sm2p256v1");

        SM2ParameterSpec sm2Spec = new SM2ParameterSpec(
                             Strings.toByteArray("Signer@Octets.ID"));

        byte[] sm2Signature = generateSM2Signature(
                                    ecKp.getPrivate(), sm2Spec,
                                    Strings.toByteArray("hello, world!"));

        System.out.println("SM2 verified: "
               + verifySM2Signature(
                    ecKp.getPublic(), sm2Spec,
                    Strings.toByteArray("hello, world!"), sm2Signature));

        sm2Signature = generateSM2Signature(
                ecKp.getPrivate(),
                Strings.toByteArray("hello, world!"));

        System.out.println("SM2 verified: "
                + verifySM2Signature(
                ecKp.getPublic(),
                Strings.toByteArray("hello, world!"), sm2Signature));
    }
}
