package com.abc.bc.gm.cert;

import com.abc.bc.gm.BCECUtil;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;


public class BCX509Cert {

    private static X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
    private static ECParameterSpec ecParameterSpec =
            new ECParameterSpec(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());
    public static final String SIGN_ALGO_SM3WITHSM2 = "SM3withSM2";


    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    public static KeyPair generateKeyPair(){
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
            kpGen.initialize(ecParameterSpec, new SecureRandom());
            KeyPair kp = kpGen.generateKeyPair();
            return kp;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static PKCS10CertificationRequest createCSR(X500Name subject, PublicKey pubKey, PrivateKey priKey,String signAlgo)
            throws OperatorCreationException {
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, pubKey);
        ContentSigner signerBuilder = new JcaContentSignerBuilder(signAlgo)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(priKey);
        return csrBuilder.build(signerBuilder);
    }

    private static JcaContentSignerBuilder makeContentSignerBuilder(PublicKey issPub) throws Exception {
        if (issPub.getAlgorithm().equals("EC")) {
            JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(SIGN_ALGO_SM3WITHSM2);
            contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            return contentSignerBuilder;
        }
        throw new Exception("Unsupported PublicKey Algorithm:" + issPub.getAlgorithm());
    }

    //生成自签发ca证书
    public static X509Certificate caCertGen(KeyPair keypair)throws Exception {
        X500Name issuerDN = new X500Name("CN=My Application,O=My Organisation,L=My City,C=DE");

        SM2PublicKey sm2SubPub = new SM2PublicKey(keypair.getPublic().getAlgorithm(),
                (BCECPublicKey) keypair.getPublic());
        byte[] csr = createCSR(issuerDN, sm2SubPub, keypair.getPrivate(), "SM3withSM2").getEncoded();

        PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);
        PublicKey subPub = BCECUtil.createPublicKeyFromSubjectPublicKeyInfo(request.getSubjectPublicKeyInfo());
        PrivateKey issPriv = keypair.getPrivate();
        PublicKey issPub = keypair.getPublic();

        Calendar c = Calendar.getInstance();
        c.add(Calendar.YEAR,1);//日期加1年
        Date startDate = new Date();
        Date endDate = c.getTime();

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(issuerDN, BigInteger.valueOf(System.currentTimeMillis()),
                startDate, endDate, request.getSubject(), subPub);

        v3CertGen.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(subPub.getEncoded())));

        v3CertGen.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(issPub.getEncoded())));

        v3CertGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));
        v3CertGen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.dataEncipherment
                | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));
        cert.checkValidity(new Date());
        cert.verify(issPub);
        return cert;
    }

    public static String saveX509ToPemFile(X509Certificate x509Cert, String path) throws Exception {
        PemObject pemCSR = new PemObject("CERTIFICATE REQUEST", x509Cert.getEncoded());
        StringWriter str = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(str);
        pemWriter.writeObject(pemCSR);
        pemWriter.close();
        str.close();
        FileOutputStream certOut = new FileOutputStream(path);
        certOut.write(str.toString().getBytes());

        return str.toString();
    }

    public static void savePrivateKey(PrivateKey priv, String keyFileName) throws IOException {
        // 保存private key
        try {
            FileOutputStream keyOut = new FileOutputStream(keyFileName);
            StringBuilder sb = new StringBuilder(300);
            sb.append("-----BEGIN PRIVATE KEY-----\n");
            String priKey = DatatypeConverter.printBase64Binary(priv.getEncoded());
            // 每64个字符输出一个换行
            int LEN = priKey.length();
            for (int ix = 0; ix < LEN; ++ix) {
                sb.append(priKey.charAt(ix));

                if ((ix + 1) % 64 == 0) {
                    sb.append('\n');
                }
            }

            sb.append("\n-----END PRIVATE KEY-----\n");
            keyOut.write(sb.toString().getBytes());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
