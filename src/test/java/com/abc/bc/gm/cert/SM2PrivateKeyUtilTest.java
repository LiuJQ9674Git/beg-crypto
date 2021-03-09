package com.abc.bc.gm.cert;

import com.abc.bc.gm.SM2Util;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SM2PrivateKeyUtilTest {
    @Test
    public void testEncoded() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException {

        KeyPair keyPair = SM2Util.generateKeyPair();
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
        BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();
        SM2PublicKey sm2PublicKey = new SM2PublicKey(publicKey.getAlgorithm(), publicKey);
        String nativePriDER = ByteUtils.toHexString(privateKey.getEncoded());
        String sm2PriDER1 = ByteUtils.toHexString(SM2PrivateKeyUtil.getEncoded(privateKey,publicKey));
        String sm2PriDER2 = ByteUtils.toHexString(SM2PrivateKeyUtil.getEncoded(privateKey,publicKey));
        if (nativePriDER.equalsIgnoreCase(sm2PriDER1)) {
            Assert.fail();
        }
        if (!sm2PriDER1.equalsIgnoreCase(sm2PriDER2)) {
            Assert.fail();
        }
        System.out.println("Native EC Private Key DER:\n" + nativePriDER.toUpperCase());
        System.out.println("SM2 EC Private Key DER:\n" + sm2PriDER1.toUpperCase());
    }
}
