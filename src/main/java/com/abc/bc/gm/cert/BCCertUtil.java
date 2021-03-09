package com.abc.bc.gm.cert;

import com.abc.bc.gm.BCECUtil;
import com.abc.bc.gm.FileUtil;
import com.abc.bc.gm.SM2Util;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * 生成、读写、证书
 * 从证书中获取公钥
 */
public class BCCertUtil {

    /**
     * 通过证书获取公钥
     * @param sm2Cert
     * @return
     */
    public static BCECPublicKey getBCECPublicKey(X509Certificate sm2Cert) {
        ECPublicKey pubKey = (ECPublicKey) sm2Cert.getPublicKey();
        ECPoint q = pubKey.getQ();
        ECParameterSpec parameterSpec = new ECParameterSpec(SM2Util.CURVE, SM2Util.G_POINT,
            SM2Util.SM2_ECC_N, SM2Util.SM2_ECC_H);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(q, parameterSpec);
        return new BCECPublicKey(pubKey.getAlgorithm(), pubKeySpec,
            BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * 校验证书姚总
     * 自签验证方式，
     * @param issuerPubKey 从颁发者CA证书中提取出来的公钥
     * @param cert         待校验的证书
     * @return
     */
    public static boolean verifyCertificate(BCECPublicKey issuerPubKey, X509Certificate cert) {
        try {
            cert.verify(issuerPubKey, BouncyCastleProvider.PROVIDER_NAME);
        } catch (Exception ex) {
            return false;
        }
        return true;
    }

    /**
     * 根据路径读取X509Certificate证书
     *
     * @param certFilePath
     * @return X509Certificate
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchProviderException
     */
    public static X509Certificate getX509Certificate(String certFilePath) throws IOException, CertificateException,
        NoSuchProviderException {
        InputStream is = null;
        try {
            is = new FileInputStream(certFilePath);
            return getX509Certificate(is);
        } finally {
            if (is != null) {
                is.close();
            }
        }
    }

    private static X509Certificate getX509Certificate(byte[] certBytes)
            throws CertificateException,
        NoSuchProviderException {
        ByteArrayInputStream bais = new ByteArrayInputStream(certBytes);
        return getX509Certificate(bais);
    }

    /**
     *
     * @param is
     * @return
     * @throws CertificateException
     * @throws NoSuchProviderException
     */
    private static X509Certificate getX509Certificate(InputStream is) throws CertificateException,
        NoSuchProviderException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509",
                BouncyCastleProvider.PROVIDER_NAME);
        return (X509Certificate) cf.generateCertificate(is);
    }

    /////////////////////////Pfx获取公钥和私钥//////////////////////////////////////////////


    /**
     * 通过pfx字节数组获取公钥
     * pfx/p12格式的证书，该证书符合PKCS#12
     * PKCS#12:描述个人信息交换语法标准。描述了将用户公钥、私钥、证书和其他相关信息打包的语法。
     * @param pfxDER
     * @param passwd
     * @return
     * @throws Exception
     */
    public static BCECPublicKey getPublicKeyFromPfx(byte[] pfxDER, String passwd) throws Exception {
        return getBCECPublicKey(getX509CertificateFromPfx(pfxDER, passwd));
    }

    /**
     * 通过Pfx获取私钥
     * @param pfxDER
     * @param passwd
     * @return
     * @throws Exception
     */
    public static BCECPrivateKey getPrivateKeyFromPfx(byte[] pfxDER, String passwd) throws Exception {
        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passwd.toCharArray());
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(pfxDER);

        ContentInfo[] infos = pfx.getContentInfos();
        if (infos.length != 2) {
            throw new Exception("Only support one pair ContentInfo");
        }

        for (int i = 0; i != infos.length; i++) {
            if (!infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData)) {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i]);
                PKCS12SafeBag[] bags = dataFact.getSafeBags();
                PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo) bags[0].getBagValue();
                PrivateKeyInfo info = encInfo.decryptPrivateKeyInfo(inputDecryptorProvider);
                BCECPrivateKey privateKey = BCECUtil.convertPKCS8ToECPrivateKey(info.getEncoded());
                return privateKey;
            }
        }

        throw new Exception("Not found Private Key in this pfx");
    }

    private static X509Certificate getX509CertificateFromPfx(byte[] pfxDER, String passwd) throws Exception {
        //
        InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passwd.toCharArray());
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(pfxDER);

        ContentInfo[] infos = pfx.getContentInfos();
        if (infos.length != 2) {
            throw new Exception("Only support one pair ContentInfo");
        }

        for (int i = 0; i != infos.length; i++) {
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData)) {
                PKCS12SafeBagFactory dataFact = new PKCS12SafeBagFactory(infos[i], inputDecryptorProvider);
                PKCS12SafeBag[] bags = dataFact.getSafeBags();
                X509CertificateHolder certHoler = (X509CertificateHolder) bags[0].getBagValue();
                return BCCertUtil.getX509Certificate(certHoler.getEncoded());
            }
        }

        throw new Exception("Not found X509Certificate in this pfx");
    }

    /////////////////////No Use /////////////////////
    public static CertPath getCertificateChain(byte[] certChainBytes) throws CertificateException,
            NoSuchProviderException {
        ByteArrayInputStream bais = new ByteArrayInputStream(certChainBytes);

        return getCertificateChain(bais);
    }

    public static byte[] getCertificateChainBytes(CertPath certChain) throws CertificateEncodingException {
        return certChain.getEncoded("PKCS7");
    }

    public static CertPath getCertificateChain(String certChainPath)
            throws IOException, CertificateException,
            NoSuchProviderException {
        InputStream is = null;
        try {
            is = new FileInputStream(certChainPath);
            return getCertificateChain(is);
        } finally {
            if (is != null) {
                is.close();
            }
        }
    }

    static CertPath getCertificateChain(InputStream is)
            throws CertificateException, NoSuchProviderException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509",
                BouncyCastleProvider.PROVIDER_NAME);
        return cf.generateCertPath(is, "PKCS7");
    }

    public static CertPath getCertificateChain(List<X509Certificate> certs)
            throws CertificateException,
            NoSuchProviderException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509",
                BouncyCastleProvider.PROVIDER_NAME);
        return cf.generateCertPath(certs);
    }
}
