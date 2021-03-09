package com.abc.crypto.tools.demo.chapter10.storage;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

/**
 * Basic example of using JKS to store a single private key and self-signed
 * certificate.
 */
public class PKCS12Example
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws Exception
    {
        PrivateCredential cred = KeyStoreUtils.createSelfSignedCredentials();

        KeyStore store = KeyStore.getInstance("PKCS12", "BC");

        store.load(null, null);

        store.setKeyEntry("key", cred.getPrivateKey(), null,
            new Certificate[] { cred.getCertificate() });

        FileOutputStream fOut = new FileOutputStream("basic.p12");

        store.store(fOut, "storePass".toCharArray());

        fOut.close();
    }
}
