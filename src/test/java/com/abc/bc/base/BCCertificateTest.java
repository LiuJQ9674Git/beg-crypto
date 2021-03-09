package com.abc.bc.base;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Iterator;

public class BCCertificateTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void certStoreExample()throws Exception{
        X509Certificate[]   chain = PKCS10CertCreateExample.buildChain();

        // create the store
        CollectionCertStoreParameters params = new CollectionCertStoreParameters(Arrays.asList(chain));
        CertStore store = CertStore.getInstance("Collection", params, "BC");

        // create the selector
        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(new X500Principal("CN=Requested Test Certificate").getEncoded());

        // print the subjects of the results
        Iterator certsIt = store.getCertificates(selector).iterator();
        while (certsIt.hasNext())
        {
            X509Certificate cert = (X509Certificate)certsIt.next();

            System.out.println(cert.getSubjectX500Principal());
        }
    }

    @Test
    public void certificateFactoryExample()throws Exception{
        // create the keys
        KeyPair pair = Utils.generateRSAKeyPair();

        // create the input stream
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        bOut.write(X509V1CreateExample.generateV1Certificate(pair).getEncoded());

        bOut.close();

        InputStream in = new ByteArrayInputStream(bOut.toByteArray());

        // create the certificate factory
        CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");

        // read the certificate
        X509Certificate x509Cert = (X509Certificate)fact.generateCertificate(in);
        byte[] pk=x509Cert.getPublicKey().getEncoded();
        String pkStr= Base64.toBase64String(pk);

        System.out.println("issuer: " + x509Cert.getIssuerX500Principal());
        System.out.println("pkStr: " + pkStr);
    }


}
