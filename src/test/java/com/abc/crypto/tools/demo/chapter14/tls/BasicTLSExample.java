package com.abc.crypto.tools.demo.chapter14.tls;

import java.security.KeyStore;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;


public class BasicTLSExample
{
    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        //Security.addProvider(new BouncyCastleJsseProvider());

        KeyStore serverStore = TLSUtils.createIdentityKeyStore();

        BasicTLSServer server = new BasicTLSServer(serverStore, TLSUtils.ID_STORE_PASSWORD);

        server.start();
        
        new Thread(new BasicTLSClient(TLSUtils.createTrustStore(serverStore))).start();
    }
}
