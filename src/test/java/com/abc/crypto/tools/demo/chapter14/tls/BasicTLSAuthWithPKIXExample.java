package com.abc.crypto.tools.demo.chapter14.tls;

import java.security.KeyStore;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;


public class BasicTLSAuthWithPKIXExample
{
    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        //Security.addProvider(new BouncyCastleJsseProvider());

        KeyStore serverStore = TLSUtils.createIdentityKeyStore();
        KeyStore clientStore = TLSUtils.createIdentityKeyStore();
        
        TLSServerWithClientAuthWithPKIX server =
            new TLSServerWithClientAuthWithPKIX(
                 serverStore, TLSUtils.ID_STORE_PASSWORD, TLSUtils.createTrustStore(clientStore));

        server.start();
        
        new Thread(new TLSClientWithClientAuth(
                TLSUtils.createTrustStore(serverStore), clientStore, TLSUtils.ID_STORE_PASSWORD))
            .start();
    }
}
