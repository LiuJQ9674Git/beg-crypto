package com.abc.bc.gm.cert;

import com.abc.bc.gm.BCECUtil;
import com.abc.bc.gm.SM2Util;
import com.abc.bc.gm.test.GMBaseTest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Test;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class SM2CertUtilTest {
    private static final String ROOT_PRI_PATH = "target/test.root.ca.pri";
    private static final String ROOT_CERT_PATH = "target/test.root.ca.cer";
    private static final String MID_PRI_PATH = "target/test.mid.ca.pri";
    private static final String MID_CERT_PATH = "target/test.mid.ca.cer";
    private static final String USER_PRI_PATH = "target/test.user.pri";
    private static final String USER_CERT_PATH = "target/test.user.cer";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 签名、验签，加解密
     */
    @Test
    public void testGetBCECPublicKey() {
        try {
            //当前测试例依赖以下测试例生成的文件，所以先调用一下
            BCX509CertReadWriter.makeCertificate("target/test4.sm2.cer",
                    "target/test4.sm2.pri");
            X509Certificate cert= BCCertUtil.getX509Certificate("target/test4.sm2.cer");
            BCECPublicKey pubKey = BCCertUtil.getBCECPublicKey(cert);
            byte[] priKey= BCX509CertReadWriter.readPrivateKey("target/test4.sm2.pri");
            ECPrivateKeyParameters priKeyParameters = BCECUtil.convertSEC1ToECPrivateKey(priKey);

            byte[] srcData="中国北京".getBytes();
            //byte[] sign = SM2Util.sign(priKeyParameters, GMBaseTest.WITH_ID, GMBaseTest.SRC_DATA);
            byte[] sign = SM2Util.sign(priKeyParameters, GMBaseTest.WITH_ID, srcData);

            System.out.println("SM2 sign with withId result:\n" +
                    ByteUtils.toHexString(sign));

            boolean flag = SM2Util.verify(pubKey, GMBaseTest.WITH_ID, srcData, sign);
            if (!flag) {
                Assert.fail("[withId] verify failed");
            }

            byte[] srcDataNoId="中国上海".getBytes();
            //sign = SM2Util.sign(priKeyParameters, GMBaseTest.SRC_DATA);
            sign = SM2Util.sign(priKeyParameters, srcDataNoId);
            System.out.println("SM2 sign without withId result:\n" +
                    ByteUtils.toHexString(sign));
            flag = SM2Util.verify(pubKey, srcDataNoId, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }

            //加密/解密 Base64
            byte[] srcDataTxt="北京朝阳".getBytes();
            byte[] cipherText = SM2Util.encrypt(pubKey, srcDataTxt);
            String strTxt=new String(Base64.encode(cipherText));
            System.out.println("SM2 encrypt result:\n" + strTxt);
            byte[] plain = SM2Util.decrypt(priKeyParameters,
                    Base64.decode(strTxt.getBytes()));
            String planTxt=new String(plain);
            System.out.println("SM2 decrypt result:\n" +planTxt);
            if (!Arrays.equals(plain, srcDataTxt)) {
                Assert.fail("plain not equals the src");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testVerifyCertificateFromFile() {
        try {

            //根证书
            X509Certificate rootCACert= BCX509CertReadWriter.readPublicKey(ROOT_CERT_PATH);
            X509Certificate midCACert = BCX509CertReadWriter.readPublicKey(MID_CERT_PATH);
            X509Certificate userCert = BCX509CertReadWriter.readPublicKey(USER_CERT_PATH);

            byte[] rootKey= BCX509CertReadWriter.readPrivateKey(ROOT_PRI_PATH);
            byte[] midKey= BCX509CertReadWriter.readPrivateKey(MID_PRI_PATH);
            byte[] userKey= BCX509CertReadWriter.readPrivateKey(USER_PRI_PATH);
            ECPrivateKeyParameters rootPriKey = BCECUtil.convertSEC1ToECPrivateKey(rootKey);
            ECPrivateKeyParameters midPriKey = BCECUtil.convertSEC1ToECPrivateKey(midKey);
            ECPrivateKeyParameters userPriKey = BCECUtil.convertSEC1ToECPrivateKey(userKey);
            //根证书是自签名，所以用自己的公钥验证自己的证书

            BCECPublicKey bcRootPub = BCCertUtil.getBCECPublicKey(rootCACert);
            if (!BCCertUtil.verifyCertificate(bcRootPub, rootCACert)) {
                Assert.fail();
            }
            //自签验证
            if (!BCCertUtil.verifyCertificate(bcRootPub, midCACert)) {
                Assert.fail();
            }
            BCECPublicKey bcMidPub = BCCertUtil.getBCECPublicKey(midCACert);
            if (!BCCertUtil.verifyCertificate(bcMidPub, userCert)) {
                Assert.fail();
            }
            //
            BCECPublicKey userMidPub = BCCertUtil.getBCECPublicKey(userCert);
            byte[] srcDataNoId="中国上海".getBytes();
            //私钥加签
            byte[] sign = SM2Util.sign(userPriKey, srcDataNoId);
            //公钥验签
            boolean flag = SM2Util.verify(userMidPub, srcDataNoId, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    @Test
    public void testVerifyCertificate() {
        try {
            long certExpire = 20L * 365 * 24 * 60 * 60 * 1000;
            //证书序号
            CertSNAllocator snAllocator = new RandomSNAllocator();
            //证书对
            KeyPair rootKP = SM2Util.generateKeyPair();

            //根证书
            X500Name rootDN = BCX509CertReadWriter.buildRootCADN();

            BCX509CertMaker rootCertMaker = new BCX509CertMaker(rootKP, certExpire,
                    rootDN, snAllocator);

            BCECPublicKey rootPub = new BCECPublicKey(rootKP.getPublic().getAlgorithm(),
                (BCECPublicKey) rootKP.getPublic());

            //CA机构不会凭空创建一个证书，需要一个公钥和一些元数据来填入证书之中，
            // 而这些信息就是存放在CSR文件之中
            //Certificate  Signing Request
            byte[] rootCSR = CommonUtil.createCSR(rootDN, rootPub,
                    rootKP.getPrivate(),
                BCX509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();

            //保存私钥
            BCX509CertReadWriter.savePriKey(ROOT_PRI_PATH, (BCECPrivateKey) rootKP.getPrivate(),
                (BCECPublicKey) rootKP.getPublic());

            //通过请求证书
            X509Certificate rootCACert = rootCertMaker.makeRootCACert(rootCSR);

            //保存公钥
            BCX509CertReadWriter.writePublicKey(ROOT_CERT_PATH, rootCACert.getEncoded());

            KeyPair midKP = SM2Util.generateKeyPair();

            //
            X500Name midDN = buildMidCADN();

            BCECPublicKey midPub = new BCECPublicKey(midKP.getPublic().getAlgorithm(),
                (BCECPublicKey) midKP.getPublic());

            byte[] midCSR = CommonUtil.createCSR(midDN, midPub, midKP.getPrivate(),
                BCX509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();

            BCX509CertReadWriter.savePriKey(MID_PRI_PATH, (BCECPrivateKey) midKP.getPrivate(),
                (BCECPublicKey) midKP.getPublic());

            //通过根证书创建
            X509Certificate midCACert = rootCertMaker.makeSubCACert(midCSR);

            BCX509CertReadWriter.writePublicKey(MID_CERT_PATH, midCACert.getEncoded());

            BCX509CertMaker midCertMaker = new BCX509CertMaker(midKP, certExpire,
                    midDN, snAllocator);
            KeyPair userKP = SM2Util.generateKeyPair();
            X500Name userDN = BCX509CertReadWriter.buildSubjectDN();

            BCECPublicKey userPub = new BCECPublicKey(userKP.getPublic().getAlgorithm(),
                (BCECPublicKey) userKP.getPublic());

            //
            byte[] userCSR = CommonUtil.createCSR(userDN, userPub, userKP.getPrivate(),
                BCX509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();

            BCX509CertReadWriter.savePriKey(USER_PRI_PATH, (BCECPrivateKey) userKP.getPrivate(),
                (BCECPublicKey) userKP.getPublic());
            X509Certificate userCert = midCertMaker.makeSSLEndEntityCert(userCSR);

            BCX509CertReadWriter.writePublicKey(USER_CERT_PATH, userCert.getEncoded());

            //根证书是自签名，所以用自己的公钥验证自己的证书
            BCECPublicKey bcRootPub = BCCertUtil.getBCECPublicKey(rootCACert);
            rootCACert = BCCertUtil.getX509Certificate(ROOT_CERT_PATH);

            if (!BCCertUtil.verifyCertificate(bcRootPub, rootCACert)) {
                Assert.fail();
            }

            midCACert = BCCertUtil.getX509Certificate(MID_CERT_PATH);
            if (!BCCertUtil.verifyCertificate(bcRootPub, midCACert)) {
                Assert.fail();
            }

            BCECPublicKey bcMidPub = BCCertUtil.getBCECPublicKey(midCACert);
            userCert = BCCertUtil.getX509Certificate(USER_CERT_PATH);
            if (!BCCertUtil.verifyCertificate(bcMidPub, userCert)) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static X500Name buildMidCADN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        builder.addRDN(BCStyle.CN, "ZZ Intermediate CA");
        return builder.build();
    }
}
