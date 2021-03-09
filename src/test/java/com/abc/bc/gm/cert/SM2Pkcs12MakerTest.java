package com.abc.bc.gm.cert;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;


/**
 * p12 创建签名
 * PKCS#12：描述个人信息交换语法标准。
 * 描述了将用户公钥、私钥、证书和其他相关信息打包的语法。
 */
public class SM2Pkcs12MakerTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final char[] TEST_P12_PASSWD = "12345678".toCharArray();
    private static final String TEST_P12_FILENAME = "target/test.p12";

    @Test
    public void testMakePkcs12() {
        try {
            BCPkcs12Maker.makePkcs12ToFile(TEST_P12_FILENAME,TEST_P12_PASSWD);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testPkcs12Sign() {
        //先生成一个pkcs12
        testMakePkcs12();

        try {
            KeyStore ks = BCPkcs12Maker.loadKeyStore(TEST_P12_FILENAME,
                    TEST_P12_PASSWD);
            PrivateKey privateKey = (BCECPrivateKey) ks.getKey("User Key",
                    TEST_P12_PASSWD);
            byte[] srcData = "1234567890123456789012345678901234567890".getBytes();
            // create signature
            Signature sign = Signature.getInstance(BCX509CertMaker.SIGN_ALGO_SM3WITHSM2,
                    "BC");
            //用指定的私钥初始化
            sign.initSign(privateKey);
            //添加要进行计算摘要的信息
            sign.update(srcData);
            //签名，返回签名的数组 , 前提是 initSign 和 update
            byte[] signatureValue = sign.sign();
            // verify signature
            Signature verify = Signature.getInstance(BCX509CertMaker.SIGN_ALGO_SM3WITHSM2,
                    "BC");
            X509Certificate cert = (X509Certificate) ks.getCertificate("User Key");
            verify.initVerify(cert);
            verify.update(srcData);
            boolean sigValid = verify.verify(signatureValue);
            Assert.assertTrue("signature validation result", sigValid);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}
