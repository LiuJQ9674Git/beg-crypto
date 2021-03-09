package com.abc.bc.gm.cert;

import com.abc.bc.gm.cert.demo.BCX509Cert;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class X509CertTest {
    public static void main(String[] args) throws Exception {
        // 生成公私钥对 ---------------------
        KeyPair kp = BCX509Cert.generateKeyPair();
        X509Certificate cert  = BCX509Cert.caCertGen(kp);
        System.out.println(cert);
        BCX509Cert.savePrivateKey(kp.getPrivate(),"privSm2.pri");
        String pemCertString = BCX509Cert.saveX509ToPemFile(cert,"certSm2.crt");
        System.out.println(pemCertString);
    }
}
