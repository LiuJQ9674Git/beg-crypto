package com.abc.crypto.tools.demo.chapter10.storage;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

import org.bouncycastle.crypto.util.PBKDFConfig;
import org.bouncycastle.crypto.util.ScryptConfig;
import org.bouncycastle.jcajce.BCFKSLoadStoreParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Example of using BCFKS to store a single private key and self-signed
 * certificate, using scrypt for the key store protection.
 */
public class BCFKSwithScryptExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws Exception
    {
        PrivateCredential cred = KeyStoreUtils.createSelfSignedCredentials();

        // specify scrypt parameters
        PBKDFConfig config = new ScryptConfig.Builder(1024, 8, 1)
                                                        .withSaltLength(20).build();

        KeyStore store = KeyStore.getInstance("BCFKS", "BC");

        // initialize empty store to use scrypt
        store.load(new BCFKSLoadStoreParameter.Builder()
                                        .withStorePBKDFConfig(config)
                                        .build());

        store.setKeyEntry("key", cred.getPrivateKey(), "keyPass".toCharArray(),
                                    new Certificate[] { cred.getCertificate() });

        FileOutputStream fOut = new FileOutputStream("scrypt.fks");

        store.store(fOut, "storePass".toCharArray());

        fOut.close();
    }
}
