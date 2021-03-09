package com.abc.signature;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.util.encoders.Base64;
import com.abc.bc.gm.FileUtil;
import com.abc.bc.gm.SM2Util;
import com.abc.bc.gm.cert.BCCertUtil;

import java.security.*;
import java.util.HashMap;
import java.util.Map;

public class SignatureSM3WithSM2
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private PublicKey publicKey = null;
    private static final Map<String, String> digestAlgs = new HashMap<String, String>();
    private static final Map<String, String> namedCurves = new HashMap<String, String>();
    private static final String TEST_PFX_PASSWD = "12345678";
    private static final String TEST_PFX_FILENAME = "target/test.pfx";

    public static String[] genSM3withSM2() throws GeneralSecurityException {
        KeyPair kp = SM2Util.generateKeyPair();
        PrivateKey sk = kp.getPrivate();
        PublicKey pk = kp.getPublic();
        byte[] skBytes = sk.getEncoded();
        byte[] pkBytes = pk.getEncoded();
        String skString = org.apache.commons.codec.binary.Base64.encodeBase64String(skBytes);
        String pkString = org.apache.commons.codec.binary.Base64.encodeBase64String(pkBytes);
        System.out.println("skString:\n" + skString);
        System.out.println("pkString:\n" + pkString);
        return new String[]{pkString,skString};
    }

    private BCECPrivateKey getPrivateKey(String keyId, String keyVersionId) throws Exception {
        byte[] pkcs12 = FileUtil.readFile(TEST_PFX_FILENAME);
        BCECPrivateKey privateKey = BCCertUtil.getPrivateKeyFromPfx(pkcs12,
                TEST_PFX_PASSWD);
        return privateKey;
    }

//    private PublicKey getPublicKey(String keyId, String keyVersionId) throws Exception {
//        byte[] pkcs12 = FileUtil.readFile(TEST_PFX_FILENAME);
//        BCECPublicKey publicKey = BCCertUtil.getPublicKeyFromPfx(pkcs12,
//                TEST_PFX_PASSWD);
//        return publicKey;
//    }
//
    /**
     * 签发证书加签
     * @param keyId
     * @param keyVersionId
     * @return
     * @throws Exception
     */
    private PublicKey getPublicKey(String keyId, String keyVersionId) throws Exception {
        byte[] pkcs12 = FileUtil.readFile(TEST_PFX_FILENAME);
        BCECPublicKey publicKey = BCCertUtil.getPublicKeyFromPfx(pkcs12,
                TEST_PFX_PASSWD);
        return publicKey;
    }

    private byte[] getZ(ECPublicKeyParameters ecPublicKeyParameters,
                        ECDomainParameters ecDomainParameters) {
        Digest digest = new SM3Digest();
        digest.reset();

        String userID = "1234567812345678";
        addUserID(digest, userID.getBytes());

        addFieldElement(digest, ecDomainParameters.getCurve().getA());
        addFieldElement(digest, ecDomainParameters.getCurve().getB());
        addFieldElement(digest, ecDomainParameters.getG().getAffineXCoord());
        addFieldElement(digest, ecDomainParameters.getG().getAffineYCoord());
        addFieldElement(digest, ecPublicKeyParameters.getQ().getAffineXCoord());
        addFieldElement(digest, ecPublicKeyParameters.getQ().getAffineYCoord());

        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }

    private void addUserID(Digest digest, byte[] userID) {
        int len = userID.length * 8;
        digest.update((byte) (len >> 8 & 0xFF));
        digest.update((byte) (len & 0xFF));
        digest.update(userID, 0, userID.length);
    }

    private void addFieldElement(Digest digest, ECFieldElement v) {
        byte[] p = v.getEncoded();
        digest.update(p, 0, p.length);
    }

    private byte[] calcSM3Digest(PublicKey pubKey, byte[] message, String algorithm) {
        X9ECParameters x9ECParameters = GMNamedCurves.getByName(namedCurves.get(algorithm));
        ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(),
                x9ECParameters.getG(), x9ECParameters.getN());
        BCECPublicKey localECPublicKey = (BCECPublicKey) pubKey;
        ECPublicKeyParameters ecPublicKeyParameters =
                new ECPublicKeyParameters(localECPublicKey.getQ(), ecDomainParameters);
        //SM3
        byte[] z = getZ(ecPublicKeyParameters, ecDomainParameters);
        Digest digest = new SM3Digest();
        digest.update(z, 0, z.length);
        digest.update(message, 0, message.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }


    private String asymmetricSign(String keyId, String keyVersionId,
                                  String algorithm, byte[] message) throws Exception {
        byte[] digest;
        if (algorithm.equals("SM2DSA")) {
            if (this.publicKey == null) {
                this.publicKey = getPublicKey(keyId, keyVersionId);
            }
            digest = calcSM3Digest(this.publicKey, message, algorithm);
        } else {
            digest = MessageDigest.getInstance(digestAlgs.get(algorithm)).digest(message);
        }

        String r= Base64.toBase64String(digest);
        System.out.println("加签结果：\t"+r);
        //a717A51EGAJDq2QG8o3fFHrsbaoNBwNLarPvulDvjHA=
        //GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=
        return r;
    }

    public String sign(String keyId, String keyVersionId,
                       String algorithm, byte[] message) throws Exception {
        return asymmetricSign(keyId, keyVersionId, algorithm, message);
    }

    static {
        digestAlgs.put("RSA_PKCS1_SHA_256", "SHA-256");
        digestAlgs.put("RSA_PSS_SHA_256", "SHA-256");
        digestAlgs.put("ECDSA_SHA_256", "SHA-256");

        namedCurves.put("SM2DSA", "sm2p256v1");
    }


}
