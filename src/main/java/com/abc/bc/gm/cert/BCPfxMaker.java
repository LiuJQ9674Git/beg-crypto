package com.abc.bc.gm.cert;

import com.abc.bc.gm.SM2Util;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCSException;
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
import java.security.cert.X509Certificate;

public class BCPfxMaker {



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
    public PKCS12PfxPdu makePfx(PrivateKey privKey, PublicKey pubKey,
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

            BCPkcs12Maker pkcs12Maker = new BCPkcs12Maker();
            KeyStore pkcs12 = pkcs12Maker.makePkcs12(subKP.getPrivate(), cert, p12Password);

            OutputStream os = Files.newOutputStream(Paths.get(p12FileName),
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            //存储
            pkcs12.store(os, p12Password);

        } catch (Exception ex) {

            throw new RuntimeException(ex.getCause());
        }
    }

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
     * 暂无使用
     * @param privKey 用户私钥
     * @param pubKey  用户公钥
     * @param chain   X509证书数组，切记这里固定了必须是3个元素的数组，
     *                且第一个必须是叶子证书、第二个为中级CA证书、
     *                第三个为根CA证书
     * @param passwd  口令
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws PKCSException
     */
    public PKCS12PfxPdu makePfx(PrivateKey privKey, PublicKey pubKey,
                                X509Certificate[] chain, String passwd)
            throws NoSuchAlgorithmException, IOException, PKCSException {
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        PKCS12SafeBagBuilder taCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[2]);
        taCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("Primary Certificate"));

        PKCS12SafeBagBuilder caCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[1]);
        caCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("Intermediate Certificate"));

        PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[0]);
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
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("User Key"));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                extUtils.createSubjectKeyIdentifier(pubKey));

        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();
        PKCS12SafeBag[] certs = new PKCS12SafeBag[3];
        certs[0] = eeCertBagBuilder.build();
        certs[1] = caCertBagBuilder.build();
        certs[2] = taCertBagBuilder.build();
        pfxPduBuilder.addEncryptedData(new BcPKCS12PBEOutputEncryptorBuilder(
                        PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC,
                        new CBCBlockCipher(new RC2Engine())).build(passwdChars),
                certs);
        pfxPduBuilder.addData(keyBagBuilder.build());
        return pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), passwdChars);
    }
}
