package com.abc.crypto.tools.demo.chapter7.certificates;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;

import static com.abc.signature.RsaUtils.generateRSAKeyPair;
import static com.abc.crypto.tools.demo.chapter7.certificates.RsaUtils.keyUnwrapOAEP;
import static com.abc.crypto.tools.demo.chapter7.certificates.RsaUtils.keyWrapOAEP;
import static com.abc.crypto.tools.demo.chapter7.certificates.Utils.createTestAESKey;

/**
 * Simple example showing secret key wrapping and unwrapping based on OAEP.
 */
public class OAEPExample
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        SecretKey aesKey = createTestAESKey();

        KeyPair kp = generateRSAKeyPair();

        byte[] wrappedKey = RsaUtils.keyWrapOAEP(kp.getPublic(), aesKey);
        
        SecretKey recoveredKey = RsaUtils.keyUnwrapOAEP(
                                    kp.getPrivate(),
                                    wrappedKey, aesKey.getAlgorithm());

        System.out.println(
            Arrays.areEqual(aesKey.getEncoded(), recoveredKey.getEncoded()));
    }
}
