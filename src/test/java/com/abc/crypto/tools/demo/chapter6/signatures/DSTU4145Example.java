package com.abc.crypto.tools.demo.chapter6.signatures;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import static com.abc.crypto.tools.demo.chapter6.signatures.DSTU4145Utils.generateDSTU4145KeyPair;
import static com.abc.crypto.tools.demo.chapter6.signatures.DSTU4145Utils.generateDSTU4145Signature;
import static com.abc.crypto.tools.demo.chapter6.signatures.DSTU4145Utils.verifyDSTU4145Signature;

/**
 * An example of using DSTU 4145-2002 to sign data and then
 * verifying the resulting signature.
 */
public class DSTU4145Example
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        KeyPair ecKp = generateDSTU4145KeyPair(0);

        byte[] dstuSig = generateDSTU4145Signature(
            ecKp.getPrivate(), Strings.toByteArray("hello, world!"));

        System.out.println("DSTU 4145-2002 verified: " +
                    verifyDSTU4145Signature(
                        ecKp.getPublic(), Strings.toByteArray("hello, world!"),
                         dstuSig));
    }
}
