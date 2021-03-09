package com.abc.crypto.tools.demo.chapter10.storage;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

import static com.abc.crypto.tools.demo.chapter10.storage.KeyStoreUtils.createSelfSignedCredentials;
/**
 * Basic example of using BCFKS to store a single private key and self-signed
 * certificate.
 */
public class BCFKSExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws Exception
    {
        PrivateCredential cred = createSelfSignedCredentials();

        KeyStore store = KeyStore.getInstance("BCFKS", "BC");

        store.load(null, null);

        store.setKeyEntry("key", cred.getPrivateKey(), "keyPass".toCharArray(),
            new Certificate[] { cred.getCertificate() });

        FileOutputStream fOut = new FileOutputStream("basic.fks");

        store.store(fOut, "storePass".toCharArray());

        fOut.close();
    }
}
