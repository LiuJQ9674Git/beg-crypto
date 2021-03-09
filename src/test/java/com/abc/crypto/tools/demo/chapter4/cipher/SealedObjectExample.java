package com.abc.crypto.tools.demo.chapter4.cipher;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

/**
 * An example of use of a SealedObject to protect a serializable object. In this
 * case we use a private key, but any serializable will do.
 */
public class SealedObjectExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = AEADUtils.createConstantKey();

        // create our interesting serializable
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(2048);

        KeyPair kp = kpGen.generateKeyPair();

        // initialize the "sealing cipher"
        Cipher wrapCipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");

        AlgorithmParameters algorithmParameters=wrapCipher.getParameters();
        wrapCipher.init(Cipher.ENCRYPT_MODE, aesKey);

        // create the sealed object from the serializable
        SealedObject sealed = new SealedObject(kp.getPrivate(), wrapCipher);

        // simulate a "wire transfer" of the sealed object.
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream    oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(sealed);

        oOut.close();

        SealedObject transmitted = (SealedObject)new ObjectInputStream(
            new ByteArrayInputStream(bOut.toByteArray())).readObject();

        // unseal transmitted, extracting the private key
        PrivateKey unwrappedKey =
                       (PrivateKey)transmitted.getObject(aesKey, "BC");
        if(null!=unwrappedKey) {
            //LiuJQ
            String alg=unwrappedKey.getAlgorithm();
            System.out.println("key: " + alg);
            System.out.println("   : " + Arrays.areEqual(
                    kp.getPrivate().getEncoded(), unwrappedKey.getEncoded()));
        }
    }
}
