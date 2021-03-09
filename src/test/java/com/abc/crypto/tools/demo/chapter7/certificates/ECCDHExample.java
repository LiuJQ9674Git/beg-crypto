package com.abc.crypto.tools.demo.chapter7.certificates;

import java.security.KeyPair;
import java.security.Security;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import static com.abc.signature.EcDsaUtils.generateECKeyPair;
import static com.abc.crypto.tools.demo.chapter7.certificates.ECDHUtils.ecGenerateAESKey;

public class ECCDHExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws Exception
    {
        // Generate the key pairs for party A and party B
        KeyPair aKp = generateECKeyPair();
        KeyPair bKp = generateECKeyPair();

        // key agreement generating a shared secret
        byte[] keyMaterial = Strings.toByteArray("For an AES key");

        SecretKey aKey = ecGenerateAESKey(
            aKp.getPrivate(), bKp.getPublic(), keyMaterial);
        SecretKey bKey = ecGenerateAESKey(
            bKp.getPrivate(), aKp.getPublic(), keyMaterial);

        // compare the two return values.
        System.out.println(
            Arrays.areEqual(aKey.getEncoded(), bKey.getEncoded()));
    }
}
