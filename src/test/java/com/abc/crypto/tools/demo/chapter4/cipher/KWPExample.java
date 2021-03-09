package com.abc.crypto.tools.demo.chapter4.cipher;

import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

import static com.abc.crypto.tools.demo.chapter4.cipher.AEADUtils.createConstantKey;

/**
 * An example of KWP style key wrapping with padding.
 */
public class KWPExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = createConstantKey();

        // generate an RSA key pair so we have something
        // interesting to work with!
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(2048);

        KeyPair kp = kpGen.generateKeyPair();

        // wrap the key
        Cipher wrapCipher = Cipher.getInstance("AESKWP", "BC");

        wrapCipher.init(Cipher.WRAP_MODE, aesKey);

        byte[] cText = wrapCipher.wrap(kp.getPrivate());

        // unwrap the key
        Cipher unwrapCipher = Cipher.getInstance("AESKWP", "BC");

        unwrapCipher.init(Cipher.UNWRAP_MODE, aesKey);
        AlgorithmParameters algorithmParameters=unwrapCipher.getParameters();
        PrivateKey unwrappedKey =
            (PrivateKey)unwrapCipher.unwrap(cText, "RSA", Cipher.PRIVATE_KEY);

        System.out.println("key: " + unwrappedKey.getAlgorithm());
        System.out.println("   : " + Arrays.areEqual(
            kp.getPrivate().getEncoded(), unwrappedKey.getEncoded()));
    }
}
