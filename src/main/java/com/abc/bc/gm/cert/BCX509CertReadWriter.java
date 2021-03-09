package com.abc.bc.gm.cert;

import com.abc.bc.gm.BCECUtil;
import com.abc.bc.gm.FileUtil;
import com.abc.bc.gm.SM2Util;
import com.abc.bc.gm.cert.exception.InvalidX500NameException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * 产生与读写CA
 */
public class BCX509CertReadWriter {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     *
     * @param pubKey 公钥文件
     * @param privateKey 私钥文件
     */
    public static void makeCertificate(String pubKey,String privateKey) {
        try {
            //证书对
            KeyPair subKP = SM2Util.generateKeyPair();
            //请求机构，不调用RootDN
            X500Name subDN = buildSubjectDN();
            BCECPublicKey sm2SubPub= new BCECPublicKey(subKP.getPublic().getAlgorithm(),
                    (BCECPublicKey) subKP.getPublic());
            //SM3withSM2
            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
                    BCX509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
            //签发机构，签发证书，调用Root
            BCX509CertMaker certMaker = buildCertMaker();
            //生成证书
            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);
            //私钥保存
            savePriKey(privateKey, (BCECPrivateKey) subKP.getPrivate(),
                    (BCECPublicKey) subKP.getPublic());
            FileUtil.writePublicKey(pubKey,cert.getEncoded());
        } catch (Exception ex) {
            throw new RuntimeException(ex.getCause());
        }
    }

    public static void savePriKey(String filePath, BCECPrivateKey priKey, BCECPublicKey pubKey) throws IOException {
        ECPrivateKeyParameters priKeyParam = BCECUtil.convertPrivateKeyToParameters(priKey);
        ECPublicKeyParameters pubKeyParam = BCECUtil.convertPublicKeyToParameters(pubKey);
        byte[] derPriKey = BCECUtil.convertECPrivateKeyToSEC1(priKeyParam, pubKeyParam);
        FileUtil.writePrivateKey(filePath,derPriKey);
    }

    public static void writePublicKey(String filePath, byte[] data) throws IOException {
        FileUtil.writePublicKey(filePath,data);
    }

    public static byte[] readPrivateKey(String filePath) throws IOException{
        return FileUtil.readPrivateKey(filePath);
    }

    /**
     * 根据路径读取X509Certificate
     * @param filePath
     * @return
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws IOException
     */
    public static X509Certificate readPublicKey(String filePath) throws CertificateException, NoSuchProviderException, IOException {
        return BCCertUtil.getX509Certificate(filePath);
    }

    public static X500Name buildSubjectDN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        builder.addRDN(BCStyle.CN, "example.org");
        builder.addRDN(BCStyle.EmailAddress, "abc@example.org");
        return builder.build();
    }

    public static X500Name buildRootCADN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        builder.addRDN(BCStyle.CN, "ZZ Root CA");
        return builder.build();
    }

    public static BCX509CertMaker buildCertMaker() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidX500NameException {
        //发证机构
        X500Name issuerName = buildRootCADN();
        //秘钥对
        KeyPair issKP = SM2Util.generateKeyPair();
        long certExpire = 20L * 365 * 24 * 60 * 60 * 1000; // 20年
        // 实际应用中可能需要使用数据库来保证证书序列号的唯一性。
        CertSNAllocator snAllocator = new RandomSNAllocator();
        return new BCX509CertMaker(issKP, certExpire, issuerName, snAllocator);
    }
}
