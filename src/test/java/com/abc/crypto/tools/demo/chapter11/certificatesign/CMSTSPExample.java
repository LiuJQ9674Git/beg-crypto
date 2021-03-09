package com.abc.crypto.tools.demo.chapter11.certificatesign;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import static com.abc.crypto.tools.demo.chapter11.certificatesign.TSPUtils.createTimeStampedSignedData;
import static com.abc.crypto.tools.demo.chapter11.certificatesign.TSPUtils.verifyTimeStampedSigner;
import static com.abc.signature.EcDsaUtils.generateECKeyPair;
import static com.abc.certificate.JcaX509Certificate.createSpecialPurposeEndEntity;
import static com.abc.certificate.JcaX509Certificate.createTrustAnchor;

/**
 * Example showing the full time-stamping of CMS SignedData
 */
public class CMSTSPExample
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        byte[] msg = Strings.toByteArray("Hello, world!");

        KeyPair selfSignedKp = generateECKeyPair();
        X509CertificateHolder selfSignedCert =
            createTrustAnchor(selfSignedKp, "SHA256withECDSA");

        CMSSignedData encapSigned = SignedDataExample.createSignedData(selfSignedKp.getPrivate(),
            selfSignedCert, msg, true);

        SignedDataExample.verifySignedEncapsulated(encapSigned.getEncoded());

        CMSTypedData cmsData = encapSigned.getSignedContent();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        cmsData.write(bOut);

        System.out.println(Strings.fromByteArray(bOut.toByteArray()));

        JcaX509CertificateConverter certConverter =
            new JcaX509CertificateConverter().setProvider("BC");

        KeyPair tspKp = generateECKeyPair();

        X509Certificate tspCert =
            certConverter.getCertificate(
                createSpecialPurposeEndEntity(
                    selfSignedCert, selfSignedKp.getPrivate(), "SHA256withECDSA",
                    tspKp.getPublic(), KeyPurposeId.id_kp_timeStamping));

        ASN1ObjectIdentifier madeUpTsaPolicyOID = new ASN1ObjectIdentifier("1.1.1");
        
        byte[] encStampedSignedData = createTimeStampedSignedData(
            encapSigned.getEncoded(),
            BigInteger.valueOf(System.currentTimeMillis()),
            tspKp.getPrivate(), tspCert,
            BigInteger.ONE, madeUpTsaPolicyOID);

        System.out.println("TSP verified: "
            + verifyTimeStampedSigner(encStampedSignedData));
    }
}
