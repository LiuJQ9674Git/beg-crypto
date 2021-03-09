package com.abc.bc.gm.cert;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.spec.ECParameterSpec;

public class SM2PrivateKeyUtil {
    public static final ASN1ObjectIdentifier ID_SM2_PUBKEY_PARAM =
            new ASN1ObjectIdentifier("1.2.156.10197.1.301");

    public static byte[] getEncoded(BCECPrivateKey privateKey, BCECPublicKey publicKey) {
        BCECPrivateKey bcecPrivateKey=new BCECPrivateKey(privateKey.getAlgorithm(), privateKey);
        DERBitString sm2PublicKey=getSM2PublicKeyDetails(publicKey);
        ECParameterSpec ecSpec = bcecPrivateKey.getParams();
        ProviderConfiguration configuration = BouncyCastleProvider.CONFIGURATION;
        ASN1Encodable params = ID_SM2_PUBKEY_PARAM;

        int orderBitLength;
        if (ecSpec == null) {
            orderBitLength = ECUtil.getOrderBitLength(configuration, null, bcecPrivateKey.getS());
        } else {
            orderBitLength = ECUtil.getOrderBitLength(configuration, ecSpec.getOrder(), bcecPrivateKey.getS());
        }

        PrivateKeyInfo info;
        ECPrivateKey keyStructure;

        if (sm2PublicKey != null) {
            keyStructure = new ECPrivateKey(orderBitLength, bcecPrivateKey.getS(), sm2PublicKey, params);
        } else {
            keyStructure = new ECPrivateKey(orderBitLength, bcecPrivateKey.getS(), params);
        }

        try {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), keyStructure);

            return info.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            return null;
        }
    }

    private static DERBitString getSM2PublicKeyDetails(BCECPublicKey pub) {
        try {

            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.
                    fromByteArray(getPubulicEncode(pub,false)));

            return info.getPublicKeyData();
        } catch (IOException e) {   // should never happen
            return null;
        }
    }

    public static byte[] getPubulicEncode(BCECPublicKey key,boolean withCompression) {
        ASN1OctetString p = ASN1OctetString.getInstance(
                new X9ECPoint(key.getQ(), withCompression).toASN1Primitive());

        // stored curve is null if ImplicitlyCa
        SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ID_SM2_PUBKEY_PARAM),
                p.getOctets());
        return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
    }
}
