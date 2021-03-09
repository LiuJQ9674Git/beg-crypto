package com.abc.crypto.tools.demo.chapter7.certificates;

import java.security.KeyPair;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import static com.abc.crypto.tools.demo.chapter7.certificates.DHUtils.generateDHKeyPair;

/**
 * Basic Diffie-Hellman MQV example showing use of two key pairs
 * per party in the protocol, with one set being regarded as ephemeral.
 */
public class MQVDHExample
{
    public static void main(String[] args)
        throws Exception
    {
        // Generate the key pairs for party A and party B
        KeyPair aKpS = DHUtils.generateDHKeyPair();
        KeyPair aKpE = DHUtils.generateDHKeyPair();    // A's ephemeral pair
        KeyPair bKpS = DHUtils.generateDHKeyPair();
        KeyPair bKpE = DHUtils.generateDHKeyPair();    // B's ephemeral pair

        // key agreement generating an AES key
        byte[] keyMaterial = Strings.toByteArray("For an AES key");

        SecretKey aKey = DHUtils.mqvGenerateAESKey(
            aKpS.getPrivate(),
            aKpE.getPublic(), aKpE.getPrivate(),
            bKpS.getPublic(), bKpE.getPublic(), keyMaterial);
        SecretKey bKey = DHUtils.mqvGenerateAESKey(
            bKpS.getPrivate(),
            bKpE.getPublic(), bKpE.getPrivate(),
            aKpS.getPublic(), aKpE.getPublic(), keyMaterial);

        // compare the two return values.
        System.out.println(
            Arrays.areEqual(aKey.getEncoded(), bKey.getEncoded()));
    }
}
