package com.abc.bc.gm.cert;

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
import com.abc.bc.gm.BCECUtil;
import com.abc.bc.gm.FileUtil;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

public class SM2PfxMakerCBTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String TEST_PFX_PASSWD = "12345678";
    private static final String TEST_PFX_FILENAME = "target/test.pfx";

    @Test
    public void testMakePfx() {
        try {
            KeyPair subKP = SM2Util.generateKeyPair();
            X500Name subDN = BCX509CertFace.buildSubjectDN();
            BCECPublicKey sm2SubPub = new BCECPublicKey(subKP.getPublic().getAlgorithm(),
                    (BCECPublicKey) subKP.getPublic());
            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
                    BCX509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
            BCX509CertMaker certMaker = BCX509CertFace.buildCertMaker();
            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);

            BCPfxMaker pfxMaker = new BCPfxMaker();
            PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
            PublicKey subPub = BCECUtil.createPublicKeyFromSubjectPublicKeyInfo(
                    request.getSubjectPublicKeyInfo());
            PKCS12PfxPdu pfx = pfxMaker.makePfx(subKP.getPrivate(), subPub, cert,
                    TEST_PFX_PASSWD);
            byte[] pfxDER = pfx.getEncoded(ASN1Encoding.DER);
            FileUtil.writeFile(TEST_PFX_FILENAME, pfxDER);
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
