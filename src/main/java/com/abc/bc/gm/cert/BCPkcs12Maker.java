package com.abc.bc.gm.cert;

import com.abc.bc.gm.BCECUtil;
import com.abc.bc.gm.FileUtil;
import com.abc.bc.gm.SM2Util;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class BCPkcs12Maker {

    /**
     * SM2Pkcs12MakerTest
     * @param p12FileName
     * @param p12Password
     * @return
     */
    public static KeyStore loadKeyStore(String p12FileName,char[] p12Password){
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");

            InputStream is = Files.newInputStream(Paths.get(p12FileName),
                    StandardOpenOption.READ);
            ks.load(is, p12Password);
            return ks;
        }catch (Exception e){
            throw new RuntimeException(e.getCause());
        }
    }

    /**
     * SM2Pkcs12MakerTest
     * @param p12FileName
     * @param p12Password
     */
    public static void makePkcs12ToFile(String p12FileName,char[] p12Password) {
        try {
            KeyPair subKP = SM2Util.generateKeyPair();
            X500Name subDN = BCX509CertReadWriter.buildSubjectDN();
//            SM2PublicKey sm2SubPub = new SM2PublicKey(subKP.getPublic().getAlgorithm(),
//                    (BCECPublicKey) subKP.getPublic());

            BCECPublicKey sm2SubPub = new BCECPublicKey(subKP.getPublic().getAlgorithm(),
                    (BCECPublicKey) subKP.getPublic());

            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
                    BCX509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
            BCX509CertMaker certMaker = BCX509CertReadWriter.buildCertMaker();
            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);

            //BCPkcs12Maker pkcs12Maker = new BCPkcs12Maker();
            KeyStore pkcs12 = makePkcs12(subKP.getPrivate(), cert, p12Password);

            OutputStream os = Files.newOutputStream(Paths.get(p12FileName),
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            //存储
            pkcs12.store(os, p12Password);

        } catch (Exception ex) {

            throw new RuntimeException(ex.getCause());
        }
    }

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
    private static KeyStore makePkcs12(PrivateKey privKey, X509Certificate[] chain, char[] passwd)
        throws KeyStoreException, NoSuchProviderException,
        NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, passwd);
        ks.setKeyEntry("User Key", privKey, passwd, chain);
        return ks;
    }

    /**
     *
     * @param privKey 用户私钥
     * @param cert    X509证书
     * @param passwd  口令
     * @return the PKCS12 keystore
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws PKCSException
     */
    private static KeyStore makePkcs12(PrivateKey privKey, X509Certificate cert, char[] passwd)
        throws KeyStoreException, NoSuchProviderException,
        NoSuchAlgorithmException, CertificateException, IOException {
      return makePkcs12(privKey, new X509Certificate[] {cert}, passwd);
    }

    /**
     * @param privKey 用户私钥
     * @param pubKey  用户公钥
     * @param cert    X509证书
     * @param passwd  口令
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws PKCSException
     */
    private static PKCS12PfxPdu makePfx(PrivateKey privKey, PublicKey pubKey,
                                X509Certificate cert, String passwd)
            throws NoSuchAlgorithmException, IOException, PKCSException {
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(cert);
        //
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("User Key"));
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                extUtils.createSubjectKeyIdentifier(pubKey));

        char[] passwdChars = passwd.toCharArray();
        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privKey,
                new BcPKCS12PBEOutputEncryptorBuilder(
                        PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
                        new CBCBlockCipher(new DESedeEngine())).build(passwdChars));
        //
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("User Key"));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                extUtils.createSubjectKeyIdentifier(pubKey));

        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();
        PKCS12SafeBag[] certs = new PKCS12SafeBag[1];
        certs[0] = eeCertBagBuilder.build();
        pfxPduBuilder.addEncryptedData(new BcPKCS12PBEOutputEncryptorBuilder(
                        PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC,
                        new CBCBlockCipher(new RC2Engine())).build(passwdChars),
                certs);
        pfxPduBuilder.addData(keyBagBuilder.build());
        return pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), passwdChars);
    }

    /**
     * 生成证书 SM2PfxMakerTest调用
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

            //BCPfxMaker pfxMaker = new BCPfxMaker();
            PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
            PublicKey subPub = BCECUtil.createPublicKeyFromSubjectPublicKeyInfo(
                    request.getSubjectPublicKeyInfo());
            PKCS12PfxPdu pfx = makePfx(subKP.getPrivate(), subPub, cert,
                    password);
            byte[] pfxDER = pfx.getEncoded(ASN1Encoding.DER);
            FileUtil.writeFile(pfxFileName, pfxDER);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
