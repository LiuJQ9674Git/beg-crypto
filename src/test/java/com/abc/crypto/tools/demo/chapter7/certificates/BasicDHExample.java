package com.abc.crypto.tools.demo.chapter7.certificates;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import static com.abc.crypto.tools.demo.chapter7.certificates.DHUtils.generateAESKey;

/**
 * Basic Diffie-Hellman example showing the use of the KeyAgreement class
 * for generating byte arrays and secret keys.
 * <b>Note</b>: this example is generating constant keys, do not use the
 * key generation code in real life unless that is what you intend!
 */
public class BasicDHExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    // Generate and print a shared secret using the A and B party key pairs.
    private static byte[] generateSecretValue(KeyPair aKp, KeyPair bKp)
        throws GeneralSecurityException
    {
        byte[] aValue = DHUtils.generateSecret(aKp.getPrivate(), bKp.getPublic());
        byte[] bValue = DHUtils.generateSecret(bKp.getPrivate(), aKp.getPublic());

        System.out.println("aS: " + Hex.toHexString(aValue));
        System.out.println("bS: " + Hex.toHexString(bValue));

        return aValue;
    }

    // Generate and print an AES key using the A and B party key pairs.
    private static SecretKey generateAESKeyValue(KeyPair aKp, KeyPair bKp)
        throws GeneralSecurityException
    {
        SecretKey aKey = DHUtils.generateAESKey(aKp.getPrivate(), bKp.getPublic());
        SecretKey bKey = DHUtils.generateAESKey(bKp.getPrivate(), aKp.getPublic());

        System.out.println("aK: " + Hex.toHexString(aKey.getEncoded()));
        System.out.println("bK: " + Hex.toHexString(bKey.getEncoded()));

        return aKey;
    }

    public static void main(String[] args)
        throws Exception
    {
        // Set up parameter spec for key pair generation
        InsecureDHUtils.insecureUtilsInit();

        // Generate the constant key pairs for party A and party B
        KeyPair aKp = InsecureDHUtils.insecureGenerateDHKeyPair();
        KeyPair bKp = InsecureDHUtils.insecureGenerateDHKeyPair();

        // key agreement generating a shared secret
        byte[] retGenSec = generateSecretValue(aKp, bKp);
        // key agreement generating an AES key
        SecretKey retAESKey = generateAESKeyValue(aKp, bKp);

        // compare the two return values.
        System.err.println(Arrays.areEqual(retGenSec, retAESKey.getEncoded()));
    }
}
