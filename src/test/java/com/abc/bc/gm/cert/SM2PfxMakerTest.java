package com.abc.bc.gm.cert;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import com.abc.bc.gm.BCECUtil;
import com.abc.bc.gm.FileUtil;
import com.abc.bc.gm.SM2Util;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.junit.Assert;
import org.junit.Test;

/**
 * pfx: Pfx证书，同时包含了公钥信息和私钥信息
 * 其中Pkcs12StoreBuilder建立一个PKCS12Store对象，PKCS12Store对象来产生一个pfx/p12格式的证书，该证书符合PKCS#12规范
 *
 * PKCS#12的ref，见RSA给出的文档：PKCS #12: Personal Information Exchange Syntax Standard
 *
 * PKCS12Store中方法load()和save()，加载和保存证书，其中的实现比较复杂，处理过程主要是对PKCS12证书内容的一组SafeBag进行判断和解包。一个PKCS12结构分析的文档：http://cid-780607117452312e.office.live.com/self.aspx/.Public/PKCS%5E3l2%E7%BB%93%E6%9E%84%E5%88%86%E6%9E%90.pdf
 *
 *
 *
 * AsymmetricKeyEntry中封装了私钥，支持属性包的附加，attributeBag，可以方便获得私钥或封装私钥
 *
 * 类似的，X509CertificateEntry封装了公钥证书，支持属性包的附加和x509certificateV3的扩展，可以从中方便获得公钥等
 * 加签，验签
 */
public class SM2PfxMakerTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String TEST_PFX_PASSWD = "12345678";
    private static final String TEST_PFX_FILENAME = "target/test.pfx";

    @Test
    public void testMakePfx() {
        try {
            BCCertUtil.makePfx(TEST_PFX_FILENAME,TEST_PFX_PASSWD);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testPfxSign() {
        //先生成一个pfx
        testMakePfx();

        try {
            byte[] pkcs12 = FileUtil.readFile(TEST_PFX_FILENAME);
            BCECPublicKey publicKey = BCCertUtil.getPublicKeyFromPfx(pkcs12,
                    TEST_PFX_PASSWD);
            BCECPrivateKey privateKey = BCCertUtil.getPrivateKeyFromPfx(pkcs12,
                    TEST_PFX_PASSWD);

            String srcData = "1234567890123456789012345678901234567890";
            byte[] sign = SM2Util.sign(privateKey, srcData.getBytes());
            boolean flag = SM2Util.verify(publicKey, srcData.getBytes(), sign);
            if (!flag) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}
