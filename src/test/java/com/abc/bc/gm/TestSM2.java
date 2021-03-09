package com.abc.bc.gm;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TestSM2 {
    private static X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
    private static ECDomainParameters ecDomainParameters = new
            ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

    private final static BouncyCastleProvider bc = new BouncyCastleProvider();
    private final static String KEY_ALGORITHM = "EC";
    private final static String SIGNATURE_ALGORITHM = "SM3withSm2";

    public static String sign(byte[] data, String privateKeyStr) throws Exception {

        byte[] keyBytes = Base64.decodeBase64(privateKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM, bc);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, bc);
        signature.initSign(priKey);
        signature.update(data);
        return Base64.encodeBase64String(signature.sign());
    }

    public static boolean verify(byte[] data, String publicKeyStr, String sign) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM, bc);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, bc);
        signature.initVerify(pubKey);
        signature.update(data);
        return signature.verify(Base64.decodeBase64(sign));
    }

    /**
     * c1||c3||c2 私钥解密
     * @param data
     * @param privateKeyStr
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, String privateKeyStr) throws Exception{
        return sm2DecryptOld(changeC1C3C2ToC1C2C3(data), privateKeyStr);
    }

    /**
     * c1||c3||c2 公钥加密
     * @param data
     * @param publicKeyStr
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String publicKeyStr) throws Exception {
        return changeC1C2C3ToC1C3C2(sm2EncryptOld(data, publicKeyStr));
    }

    /**
     * bc加解密使用旧标c1||c2||c3，此方法在加密后调用，将结果转化为c1||c3||c2
     * @param c1c2c3
     * @return
     */
    private static byte[] changeC1C2C3ToC1C3C2(byte[] c1c2c3) {
        final int c1Len = (x9ECParameters.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        final int c3Len = 32;
        byte[] result = new byte[c1c2c3.length];
        System.arraycopy(c1c2c3, 0, result, 0, c1Len);
        System.arraycopy(c1c2c3, c1c2c3.length - c3Len, result, c1Len, c3Len);
        System.arraycopy(c1c2c3, c1Len, result, c1Len + c3Len, c1c2c3.length - c1Len - c3Len);
        return result;
    }


    /**
     * bc加解密使用旧标c1||c2||c3，此方法在解密前调用，将c1||c3||c2密文转化为c1||c2||c3再去解密
     * @param c1c3c2
     * @return
     */
    private static byte[] changeC1C3C2ToC1C2C3(byte[] c1c3c2) {
        final int c1Len = (x9ECParameters.getCurve().getFieldSize() + 7) / 8 * 2 + 1;
        final int c3Len = 32;
        byte[] result = new byte[c1c3c2.length];
        System.arraycopy(c1c3c2, 0, result, 0, c1Len);
        System.arraycopy(c1c3c2, c1Len + c3Len, result, c1Len, c1c3c2.length - c1Len - c3Len);
        System.arraycopy(c1c3c2, c1Len, result, c1c3c2.length - c3Len, c3Len);
        return result;
    }


    /**
     * c1||c2||c3
     * @param data
     * @param publicKeyStr
     * @return
     * @throws Exception
     */
    private static byte[] sm2EncryptOld(byte[] data, String publicKeyStr) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM, bc);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        BCECPublicKey localECPublicKey = (BCECPublicKey) pubKey;
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(localECPublicKey.getQ(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        return sm2Engine.processBlock(data, 0, data.length);
    }

    /**
     * c1||c2||c3
     * @param data
     * @param privateKeyStr
     * @return
     * @throws Exception
     */
    private static byte[] sm2DecryptOld(byte[] data, String privateKeyStr) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM, bc);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
        BCECPrivateKey localECPrivateKey = (BCECPrivateKey) priKey;
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(localECPrivateKey.getD(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, ecPrivateKeyParameters);
        return sm2Engine.processBlock(data, 0, data.length);
    }

    public static String read(String filePath) throws IOException {
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(new File(filePath)));
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            int size = 0;
            byte[] temp = new byte[128];
            while ((size = bis.read(temp)) > 0) {
                outputStream.write(temp, 0, size);
            }
            return new String(outputStream.toByteArray());
        }
    }

    public static void main(String[] args) throws Exception {
        String priPath = "/Users/liujianqiang/Desktop/RJ-DEV/08pci/08pci/02source/framework-dss/framework-cryption/src/main/resources/pri_pkcs8.pem";
        String pubPath = "/Users/liujianqiang/Desktop/RJ-DEV/08pci/08pci/02source/framework-dss/framework-cryption/src/main/resources/pub.pem";

        String data = "123213";
        String sign = sign(data.getBytes(), read(priPath));
        boolean verify = verify(data.getBytes(), read(pubPath), sign);
        System.out.println(verify);

        byte[] encryptByPublicKey = encryptByPublicKey(data.getBytes(), read(pubPath));
        byte[] decryptByPrivateKey = decryptByPrivateKey(encryptByPublicKey, read(priPath));
        System.out.println(new String(decryptByPrivateKey));
    }

}