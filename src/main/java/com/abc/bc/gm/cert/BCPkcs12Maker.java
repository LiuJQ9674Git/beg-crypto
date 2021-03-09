package com.abc.bc.gm.cert;

import com.abc.bc.gm.BCECUtil;
import com.abc.bc.gm.FileUtil;
import com.abc.bc.gm.SM2Util;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCSException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class BCPkcs12Maker {

    /**
     * @param privKey 用户私钥
     * @param chain   X509证书数组，
     *                第一个（index 0）为privKey对应的证书，index i+1 是index i的CA证书
     * @param passwd  口令
     * @return the PKCS#12 keystore
     * @throws NoSuchProviderException 
     * @throws KeyStoreException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws PKCSException
     */
    public KeyStore makePkcs12(PrivateKey privKey, X509Certificate[] chain, char[] passwd)
        throws KeyStoreException, NoSuchProviderException,
        NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, passwd);
        ks.setKeyEntry("User Key", privKey, passwd, chain);
        return ks;
    }

    /**
     * @param privKey 用户私钥
     * @param cert    X509证书
     * @param passwd  口令
     * @return the PKCS12 keystore
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws PKCSException
     */
    public KeyStore makePkcs12(PrivateKey privKey, X509Certificate cert, char[] passwd)
        throws KeyStoreException, NoSuchProviderException,
        NoSuchAlgorithmException, CertificateException, IOException {
      return makePkcs12(privKey, new X509Certificate[] {cert}, passwd);
    }

    /**
     * 生成证书
     * @param pfxFileName
     * @param password
     */
    public static void makePfx(String pfxFileName,String password) {
        try {
            KeyPair subKP = SM2Util.generateKeyPair();
            X500Name subDN = BCX509CertReadWriter.buildSubjectDN();
            BCECPublicKey sm2SubPub = new BCECPublicKey(subKP.getPublic().getAlgorithm(),
                    (BCECPublicKey) subKP.getPublic());
            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
                    BCX509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
            BCX509CertMaker certMaker = BCX509CertReadWriter.buildCertMaker();
            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);

            BCPfxMaker pfxMaker = new BCPfxMaker();
            PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
            PublicKey subPub = BCECUtil.createPublicKeyFromSubjectPublicKeyInfo(
                    request.getSubjectPublicKeyInfo());
            PKCS12PfxPdu pfx = pfxMaker.makePfx(subKP.getPrivate(), subPub, cert,
                    password);
            byte[] pfxDER = pfx.getEncoded(ASN1Encoding.DER);
            FileUtil.writeFile(pfxFileName, pfxDER);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
