package com.abc.bc.base;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import com.abc.bc.gm.SM2Util;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.*;

import org.apache.commons.codec.binary.Base64;

public class BCTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void RandomKeyElGamalExample()throws Exception{
        byte[]           input = new byte[] { (byte)0xbe, (byte)0xef };
        Cipher	         cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");

        SecureRandom     random = Utils.createFixedRandom();

        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ElGamal", "BC");

        generator.initialize(256, random);

        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();

        System.out.println("input : " + Utils.toHex(input));

        // encryption step

        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

        byte[] cipherText = cipher.doFinal(input);

        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step

        cipher.init(Cipher.DECRYPT_MODE, privKey);

        byte[] plainText = cipher.doFinal(cipherText);

        System.out.println("plain : " + Utils.toHex(plainText));
    }

    @Test
    public void namedCurveExample()throws Exception{
        KeyPairGenerator   keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");

        keyGen.initialize(ecSpec, Utils.createFixedRandom());

        // set up
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair      aPair = keyGen.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair      bPair = keyGen.generateKeyPair();

        // two party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        // generate the key bytes
        MessageDigest	hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());

        System.out.println(Utils.toHex(aShared));
        System.out.println(Utils.toHex(bShared));
    }

    @Test
    public void pkcs1PaddedRSAExample()throws Exception{
        byte[]           input = new byte[] { 0x00, (byte)0xbe, (byte)0xef };
        Cipher	         cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");
        SecureRandom     random = Utils.createFixedRandom();

        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");

        generator.initialize(256, random);

        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();

        System.out.println("input : " + Utils.toHex(input));

        // encryption step

        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

        byte[] cipherText = cipher.doFinal(input);

        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step

        cipher.init(Cipher.DECRYPT_MODE, privKey);

        byte[] plainText = cipher.doFinal(cipherText);

        System.out.println("plain : " + Utils.toHex(plainText));
    }

    @Test
    public void pkcs1SignatureExample()throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");

        //keyGen.initialize(512, new SecureRandom());
        keyGen.initialize(2048, new SecureRandom());

        KeyPair             keyPair = keyGen.generateKeyPair();
        //SHA256withRSA
        //Signature           signature = Signature.getInstance("SHA1withRSA", "BC");
        Signature           signature = Signature.getInstance("SHA256withRSA", "BC");

        // generate a signature
        signature.initSign(keyPair.getPrivate(), Utils.createFixedRandom());

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        signature.update(message);

        byte[]  sigBytes = signature.sign();

        // verify a signature
        signature.initVerify(keyPair.getPublic());

        signature.update(message);

        if (signature.verify(sigBytes))
        {
            System.out.println("signature verification succeeded.");
        }
        else
        {
            System.out.println("signature verification failed.");
        }
    }

    @Test
    public void basicPSSExample()throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA",
                "BC");

        keyGen.initialize(512, new SecureRandom());

        KeyPair             keyPair = keyGen.generateKeyPair();
        Signature           signature = Signature.getInstance("SHA1withRSAandMGF1",
                "BC");

        // generate a signature
        signature.initSign(keyPair.getPrivate(), Utils.createFixedRandom());

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        signature.update(message);

        byte[]  sigBytes = signature.sign();

        // verify a signature
        signature.initVerify(keyPair.getPublic());

        // set the parameters
        signature.setParameter(new PSSParameterSpec("SHA-1", "MGF1",
                MGF1ParameterSpec.SHA1, 20, 1));

        signature.update(message);

        if (signature.verify(sigBytes))
        {
            System.out.println("signature verification succeeded.");
        }
        else
        {
            System.out.println("signature verification failed.");
        }
    }

    @Test
    public void baseRSAExample() throws Exception {
        byte[] input = new byte[]{(byte) 0xbe, (byte) 0xef};
        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");

        // create the keys

        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
                new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
                new BigInteger("11", 16));
        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(
                new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
                new BigInteger("57791d5430d593164082036ad8b29fb1", 16));

        RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
        RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);

        System.out.println("input : " + Utils.toHex(input));

        // encryption step

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);

        byte[] cipherText = cipher.doFinal(input);

        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step

        cipher.init(Cipher.DECRYPT_MODE, privKey);

        byte[] plainText = cipher.doFinal(cipherText);

        System.out.println("plain : " + Utils.toHex(plainText));
    }

    @Test
    public void basicECDSAExample()throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA",
                "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");

        keyGen.initialize(ecSpec, new SecureRandom());

        KeyPair             keyPair = keyGen.generateKeyPair();
        Signature           signature = Signature.getInstance("ECDSA",
                "BC");

        // generate a signature

        signature.initSign(keyPair.getPrivate(), Utils.createFixedRandom());

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        signature.update(message);

        byte[]  sigBytes = signature.sign();

        // verify a signature

        signature.initVerify(keyPair.getPublic());

        signature.update(message);

        if (signature.verify(sigBytes))
        {
            System.out.println("signature verification succeeded.");
        }
        else
        {
            System.out.println("signature verification failed.");
        }
    }

    @Test
    public void basicECDHExample()throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        EllipticCurve curve = new EllipticCurve(
                new ECFieldFp(
                        new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff",
                                16)), // p
                new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc",
                        16), // a
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
                        16)); // b

        ECParameterSpec  ecSpec = new ECParameterSpec(
                curve,
                new ECPoint(
                        new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
                                16),
                        new BigInteger("f8e6d46a003725879cefee1294db32298c06885ee186b7ee",
                                16)), // G
                new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831",
                        16), // order
                1); // h

        keyGen.initialize(ecSpec, Utils.createFixedRandom());

        // set up
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair      aPair = keyGen.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair      bPair = keyGen.generateKeyPair();

        // two party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        // generate the key bytes
        MessageDigest	hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());

        System.out.println(Utils.toHex(aShared));
        System.out.println(Utils.toHex(bShared));
    }


    @Test
    public void basicDSAExample()throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "BC");

        keyGen.initialize(512, new SecureRandom());

        KeyPair             keyPair = keyGen.generateKeyPair();
        Signature           signature = Signature.getInstance("DSA", "BC");

        // generate a signature
        signature.initSign(keyPair.getPrivate(), Utils.createFixedRandom());

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        signature.update(message);

        byte[]  sigBytes = signature.sign();

        // verify a signature
        signature.initVerify(keyPair.getPublic());

        signature.update(message);

        if (signature.verify(sigBytes))
        {
            System.out.println("signature verification succeeded.");
        }
        else
        {
            System.out.println("signature verification failed.");
        }

    }
    @Test
    public void basicDHExample() throws Exception {
        BigInteger g512 = new BigInteger(
                "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7"
                        + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b"
                        + "410b7a0f12ca1cb9a428cc", 16);
        BigInteger p512 = new BigInteger(
                "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
                        + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b"
                        + "f0573bf047a3aca98cdf3b", 16);


        DHParameterSpec dhParams = new DHParameterSpec(p512, g512);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

        keyGen.initialize(dhParams, Utils.createFixedRandom());

        // set up
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair aPair = keyGen.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair bPair = keyGen.generateKeyPair();

        // two party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        //      generate the key bytes
        MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());

        System.out.println(Utils.toHex(aShared));
        System.out.println(Utils.toHex(bShared));

    }

    @Test
    public void algorithmParameterExample() throws Exception {
        byte[] input = new byte[]{(byte) 0xbe, (byte) 0xef};
        Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
        SecureRandom random = Utils.createFixedRandom();

        // create the parameters
        AlgorithmParameterGenerator a = AlgorithmParameterGenerator.
                getInstance("ElGamal", "BC");

        a.init(256, random);

        AlgorithmParameters params = a.generateParameters();
        AlgorithmParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.
                getInstance("ElGamal", "BC");

        generator.initialize(dhSpec, random);

        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();

        System.out.println("input : " + Utils.toHex(input));

        // encryption step

        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

        byte[] cipherText = cipher.doFinal(input);

        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step

        cipher.init(Cipher.DECRYPT_MODE, privKey);

        byte[] plainText = cipher.doFinal(cipherText);

        System.out.println("plain : " + Utils.toHex(plainText));
    }

    @Test
    public void aesWrapRSAExample() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        SecureRandom random = new SecureRandom();

        KeyPairGenerator fact = KeyPairGenerator.getInstance("RSA", "BC");
        fact.initialize(1024, new SecureRandom());

        KeyPair keyPair = fact.generateKeyPair();
        Key wrapKey = Utils.createKeyForAES(256, random);

        // wrap the RSA private key
        cipher.init(Cipher.WRAP_MODE, wrapKey);

        byte[] wrappedKey = cipher.wrap(keyPair.getPrivate());

        // unwrap the RSA private key
        cipher.init(Cipher.UNWRAP_MODE, wrapKey);

        Key key = cipher.unwrap(wrappedKey, "RSA", Cipher.PRIVATE_KEY);

        if (keyPair.getPrivate().equals(key)) {
            //Key recovered.
            System.out.println("Key recovered.");
        } else {
            System.out.println("Key recovery failed.");
        }
    }

    @Test
    public void tamperedWithDigestExample() throws Exception {
        SecureRandom random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key key = Utils.createKeyForAES(256, random);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        String input = "Transfer 0000100 to AC 1234-5678";
        MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");

        System.out.println("input : " + input);

        // encryption step

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + hash.getDigestLength())];

        int ctLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);

        hash.update(Utils.toByteArray(input));

        ctLength += cipher.doFinal(hash.digest(), 0, hash.getDigestLength(), cipherText, ctLength);

        // tampering step

        cipherText[9] ^= '0' ^ '9';

        // decryption step

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
        int messageLength = plainText.length - hash.getDigestLength();

        hash.update(plainText, 0, messageLength);

        byte[] messageHash = new byte[hash.getDigestLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);

        System.out.println("plain : " + Utils.toString(plainText, messageLength) +
                " verified: " + MessageDigest.isEqual(hash.digest(), messageHash));

    }

    @Test
    public void tamperedWithHMacExample() throws Exception {
        SecureRandom random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key key = Utils.createKeyForAES(256, random);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        String input = "Transfer 0000100 to AC 1234-5678";
        Mac hMac = Mac.getInstance("HMacSHA1", "BC");
        Key hMacKey = new SecretKeySpec(key.getEncoded(), "HMacSHA1");

        System.out.println("input : " + input);

        // encryption step

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + hMac.getMacLength())];

        int ctLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);

        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(input));

        ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherText, ctLength);

        // tampering step

        cipherText[9] ^= '0' ^ '9';

        // replace digest

        // ?

        // decryption step

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
        int messageLength = plainText.length - hMac.getMacLength();

        hMac.init(hMacKey);
        hMac.update(plainText, 0, messageLength);

        byte[] messageHash = new byte[hMac.getMacLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);

        System.out.println("plain : " + Utils.toString(plainText, messageLength) +
                " verified: " + MessageDigest.isEqual(hMac.doFinal(), messageHash));

    }

    @Test
    public void pkCS5Scheme1Test() throws Exception {
        char[] password = "hello".toCharArray();
        byte[] salt = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
        byte[] input = new byte[]{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        int iterationCount = 100;

        System.out.println("input  : " + Utils.toHex(input));

        // encryption step using regular PBE
        Cipher cipher = Cipher.getInstance("PBEWithSHA1AndDES", "BC");
        SecretKeyFactory fact = SecretKeyFactory.getInstance("PBEWithSHA1AndDES", "BC");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iterationCount);

        cipher.init(Cipher.ENCRYPT_MODE, fact.generateSecret(pbeKeySpec));

        byte[] enc = cipher.doFinal(input);

        System.out.println("encrypt: " + Utils.toHex(enc));

        // decryption step - using the local implementation
        cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");

        PKCS5Scheme1 pkcs5s1 = new PKCS5Scheme1(MessageDigest.getInstance("SHA-1",
                "BC"));

        byte[] derivedKey = pkcs5s1.generateDerivedKey(password, salt, iterationCount);

        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(derivedKey, 0, 8, "DES"),
                new IvParameterSpec(derivedKey, 8, 8));

        byte[] dec = cipher.doFinal(enc);

        System.out.println("decrypt: " + Utils.toHex(dec));
    }

    @Test
    public void digestIOExample() throws Exception {
        byte[] input = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        ;

        MessageDigest hash = MessageDigest.getInstance("SHA1");

        System.out.println("input     : " + Utils.toHex(input));

        // input pass

        ByteArrayInputStream bIn = new ByteArrayInputStream(input);
        DigestInputStream dIn = new DigestInputStream(bIn, hash);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = dIn.read()) >= 0) {
            bOut.write(ch);
        }

        byte[] newInput = bOut.toByteArray();

        System.out.println("in digest : " + Utils.toHex(dIn.getMessageDigest().digest()));

        // output pass

        bOut = new ByteArrayOutputStream();

        DigestOutputStream dOut = new DigestOutputStream(bOut, hash);

        dOut.write(newInput);

        dOut.close();

        System.out.println("out digest: " + Utils.toHex(dOut.getMessageDigest().digest()));
    }

    @Test
    public void cipherMacExample() throws Exception {
        SecureRandom random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key key = Utils.createKeyForAES(256, random);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        String input = "Transfer 0000100 to AC 1234-5678";
        Mac mac = Mac.getInstance("DES", "BC");
        byte[] macKeyBytes = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        Key macKey = new SecretKeySpec(macKeyBytes, "DES");

        System.out.println("input : " + input);

        // encryption step

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + mac.getMacLength())];

        int ctLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);

        mac.init(macKey);
        mac.update(Utils.toByteArray(input));

        ctLength += cipher.doFinal(mac.doFinal(), 0, mac.getMacLength(), cipherText, ctLength);

        // decryption step

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
        int messageLength = plainText.length - mac.getMacLength();

        mac.init(macKey);
        mac.update(plainText, 0, messageLength);

        byte[] messageHash = new byte[mac.getMacLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);

        System.out.println("plain : " + Utils.toString(plainText, messageLength) + " verified: " + MessageDigest.isEqual(mac.doFinal(), messageHash));

    }

    @Test
    public void simpleCBCExample() throws Exception {
        byte[] input = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        byte[] keyBytes = new byte[]{
                0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
        byte[] ivBytes = new byte[]{
                0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");


        System.out.println("input : " + Utils.toHex(input));

        // encryption pass

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);

        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);

        // decryption pass

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];

        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);

        ptLength += cipher.doFinal(plainText, ptLength);

        System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
    }

    @Test
    public void simpleCTRExample() throws Exception {
        byte[] input = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        byte[] keyBytes = new byte[]{
                0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
        byte[] ivBytes = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("DES/CTR/NoPadding", "BC");


        System.out.println("input : " + Utils.toHex(input));

        // encryption pass

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);

        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);

        // decryption pass

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];

        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);

        ptLength += cipher.doFinal(plainText, ptLength);

        System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
    }


    @Test
    public void simpleECBExample() throws Exception {
        byte[] input = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        byte[] keyBytes = new byte[]{
                0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS7Padding", "BC");


        System.out.println("input : " + Utils.toHex(input));

        // encryption pass

        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);

        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);

        // decryption pass

        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];

        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);

        ptLength += cipher.doFinal(plainText, ptLength);

        System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
    }

    @Test
    public void keyGeneratorExample() throws Exception {
        byte[] input = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        byte[] ivBytes = new byte[]{
                0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");

        generator.init(192);

        Key encryptionKey = generator.generateKey();

        System.out.println("key   : " + Utils.toHex(encryptionKey.getEncoded()));

        System.out.println("input : " + Utils.toHex(input));

        // encryption pass

        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));

        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);

        ctLength += cipher.doFinal(cipherText, ctLength);

        // decryption pass

        Key decryptionKey = new SecretKeySpec(encryptionKey.getEncoded(), encryptionKey.getAlgorithm());

        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(ivBytes));

        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];

        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);

        ptLength += cipher.doFinal(plainText, ptLength);

        System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
    }

    @Test
    public void inlineIvCBCExample() throws Exception {
        byte[] input = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        byte[] keyBytes = new byte[]{
                0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
        byte[] ivBytes = new byte[]{
                0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");


        System.out.println("input : " + Utils.toHex(input));

        // encryption pass

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] cipherText = new byte[cipher.getOutputSize(ivBytes.length + input.length)];

        int ctLength = cipher.update(ivBytes, 0, ivBytes.length, cipherText, 0);

        ctLength += cipher.update(input, 0, input.length, cipherText, ctLength);

        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);

        // decryption pass

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] buf = new byte[cipher.getOutputSize(ctLength)];

        int bufLength = cipher.update(cipherText, 0, ctLength, buf, 0);

        bufLength += cipher.doFinal(buf, bufLength);

        // remove the iv from the start of the message

        byte[] plainText = new byte[bufLength - ivBytes.length];

        System.arraycopy(buf, ivBytes.length, plainText, 0, plainText.length);

        System.out.println("plain : " + Utils.toHex(plainText, plainText.length)
                + " bytes: " + plainText.length);
    }

    @Test
    public void simplePolicyTest() throws Exception {
        byte[] data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

        // create a 64 bit secret key from raw bytes

        SecretKey key64 = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02,
                0x03, 0x04, 0x05, 0x06, 0x07}, "Blowfish");

        // create a cipher and attempt to encrypt the data block with our key

        Cipher c = Cipher.getInstance("Blowfish/ECB/NoPadding");

        c.init(Cipher.ENCRYPT_MODE, key64);
        c.doFinal(data);
        System.out.println("64 bit test: passed");

        // create a 192 bit secret key from raw bytes

        SecretKey key192 = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02,
                0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                0x17}, "Blowfish");

        // now try encrypting with the larger key

        c.init(Cipher.ENCRYPT_MODE, key192);
        c.doFinal(data);
        System.out.println("192 bit test: passed");

        System.out.println("Tests completed");
    }

    @Test
    public void precedenceTest()
            throws Exception {
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        //SunJCE version 1.8
        System.out.println(cipher.getProvider());

        cipher = Cipher.getInstance("Blowfish/ECB/NoPadding", "BC");
        //BC version 1.65
        System.out.println(cipher.getProvider());
    }


    @Test
    public void printSHA1() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA1");
            System.out.println(
                    digest.getProvider().getName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            System.out.println(MessageDigest.getInstance("SHA1", "BC")
                    .getProvider().getName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testBlowfish() {
        try {
            Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(new byte[32], "Blowfish"));
            System.out.print("true");
        } catch (NoSuchAlgorithmException e) {
            //throw e;
        } catch (Exception e) {
            System.out.print("false");
        }


    }

    /**
     * ??????????????????????????????????????????????????????????????????????????????????????????
     * Provider?????????Service?????????????????????????????????????????????????????????????????????Service??????
     * public synchronized Service getService(String type, String algorithm)
     * ??????????????????????????????Provider?????????Service??????????????????
     */
    @Test
    public void printBouncyCastleProviderService() {
        Provider provider = new BouncyCastleProvider();
        Map<String, StringBuilder> typeAlg = new HashMap<String, StringBuilder>();
        for (Provider.Service service : provider.getServices()) {
            if (!typeAlg.containsKey(service.getType()))
                typeAlg.put(service.getType(), new StringBuilder());
            typeAlg.get(service.getType()).append(service.getAlgorithm()).append(",");
        }
        for (Map.Entry entry : typeAlg.entrySet())
            System.out.println(entry.getKey() + ": " + entry.getValue());
    }

    /**
     * Provider????????????Properties??????????????????????????????????????????Provider?????????
     */
    @Test
    public void printBouncyCastleProvider() {
        Provider provider = new BouncyCastleProvider();
        for (Map.Entry entry : provider.entrySet())
            System.out.println(entry.getKey() + ": " + entry.getValue());
    }

    @Test
    public void printProviderAttr() {
        Provider[] arr = Security.getProviders();
        for (int i = 0; i < arr.length; i++) {
            Set keys = arr[i].keySet();
            for (Iterator it = keys.iterator(); it.hasNext(); ) {
                String key = (String) it.next();
                // ??????keys?????????????????????????????????????????????????????????????????????????????????????????????
                // ????????????????????????????????????????????????????????????????????????????????????????????????
                // 1???????????????????????????????????????????????????Provider.id name??? ??? ???Provider.id version??????
                // 2???????????????????????????????????????????????????TransformService.http://www.w3.org/2001/10/xml-exc-c14n
                // # MechanismType??? ??? ???TransformService.http://www.w3.org/TR/1999/REC-xpath-19991116 MechanismType??????
                key = key.split(" ")[0];
                System.out.println("key : " + key + "\nvalue:" + arr[i].get(key) + "\n");
            }
        }


    }

    @Test
    public void printProvider() {
        Provider[] arr = Security.getProviders();
        for (int i = 0; i < arr.length; i++) {
            System.out.println("?????????" + arr[i].getName() +
                    "\n?????????" + arr[i].getVersion() + "\n?????????" +
                    arr[i].getInfo() + "\n");
        }


    }

    @Test
    public void testMessageDigest() throws Exception {
        // ??????BouncyCastle:
        // ?????????????????????:
        MessageDigest md = MessageDigest.getInstance("RipeMD160");
        md.update("HelloWorld".getBytes("UTF-8"));
        byte[] result = md.digest();
        System.out.println(new BigInteger(1, result).toString(16));
    }

    @Test
    /**
     * Hmac?????????????????????????????????????????????????????????
     * ???????????????Hash-based Message Authentication Code?????????????????????????????????????????????
     * Hmac???????????????????????????????????????????????????????????????????????????MD5????????????????????????HmacMD5????????????????????????????????????MD5???
     */
    public void testHmac() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
        SecretKey key = keyGen.generateKey();
        // ?????????????????????key:
        byte[] skey = key.getEncoded();
        System.out.println(new BigInteger(1, skey).toString(16));
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(key);
        mac.update("HelloWorld".getBytes("UTF-8"));
        byte[] result = mac.doFinal();
        System.out.println(new BigInteger(1, result).toString(16));

    }

    /**
     * ??????	????????????	       ????????????	                         ????????????
     * DES	56/64	     ECB/CBC/PCBC/CTR/...	    NoPadding/PKCS5Padding/
     * AES	128/192/256	ECB/CBC/PCBC/CTR/...	NoPadding/PKCS5Padding/PKCS7Padding/
     * IDEA	128 	    ECB	                    PKCS5Padding/PKCS7Padding/
     */
    @Test
    public void mainEncryptECB() throws Exception {
        // ??????:
        String message = "Hello, world!";
        System.out.println("Message: " + message);
        // 128????????? = 16 bytes Key:
        byte[] key = "1234567890abcdef".getBytes("UTF-8");
        // ??????:
        byte[] data = message.getBytes("UTF-8");
        byte[] encrypted = encryptECB(key, data);
        System.out.println("Encrypted: " + Base64.encodeBase64String(encrypted));
        // ??????:
        byte[] decrypted = decryptECB(key, encrypted);
        System.out.println("Decrypted: " + new String(decrypted, "UTF-8"));
    }

    // ??????:
    public static byte[] encryptECB(byte[] key, byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKey keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(input);
    }

    // ??????:
    public static byte[] decryptECB(byte[] key, byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKey keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(input);
    }

    @Test
    /**
     * ECB?????????????????????AES???????????????????????????????????????????????????????????????????????????????????????????????????
     * ?????????????????????????????????????????????????????????????????????????????????CBC???????????????????????????????????????IV?????????
     * ???????????????????????????????????????????????????????????????
     */
    public void mainEncryptCBC() throws Exception {
        // ??????:
        String message = "Hello, world! ??????";
        System.out.println("Message: " + message);
        // 256????????? = 32 bytes Key:
        byte[] key = "1234567890abcdef1234567890abcdef".getBytes("UTF-8");
        // ??????:
        byte[] data = message.getBytes("UTF-8");
        byte[] encrypted = encryptCBC(key, data);
        System.out.println("Encrypted: " + Base64.encodeBase64String(encrypted));
        // ??????:
        byte[] decrypted = decryptCBC(key, encrypted);
        System.out.println("Decrypted: " + new String(decrypted, "UTF-8"));
    }

    // ??????:
    public static byte[] encryptCBC(byte[] key, byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        // CBC????????????????????????16 bytes???initialization vector:
        SecureRandom sr = SecureRandom.getInstanceStrong();
        byte[] iv = sr.generateSeed(16);
        IvParameterSpec ivps = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivps);
        byte[] data = cipher.doFinal(input);
        // IV?????????????????????IV?????????????????????:
        return join(iv, data);
    }

    // ??????:
    public static byte[] decryptCBC(byte[] key, byte[] input) throws Exception {
        // ???input?????????IV?????????:
        byte[] iv = new byte[16];
        byte[] data = new byte[input.length - 16];
        System.arraycopy(input, 0, iv, 0, 16);
        System.arraycopy(input, 16, data, 0, data.length);
        // ??????:
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivps = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivps);
        return cipher.doFinal(data);
    }

    public static byte[] join(byte[] bs1, byte[] bs2) {
        byte[] r = new byte[bs1.length + bs2.length];
        System.arraycopy(bs1, 0, r, 0, bs1.length);
        System.arraycopy(bs2, 0, r, bs1.length, bs2.length);
        return r;
    }

    /**
     * AES??????????????????????????????????????????????????????????????????128/192/256??????
     * ??????????????????WinZip/WinRAR???????????????????????????????????????
     * <p>
     * ?????????????????????????????????????????????????????????????????????????????????????????????????????????
     * ????????????????????????????????????????????????128?????????????????????16????????????
     * <p>
     * ????????????????????????????????????????????????6??????8?????????????????????????????????????????????
     * <p>
     * ???????????????????????????????????????????????????AES?????????????????????????????????????????????128/192/256?????????
     * ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
     * ?????????????????????PBE???????????????????????????????????????????????????????????????????????????
     * <p>
     * PBE??????Password Based Encryption?????????????????????????????????
     * key = generate(userPassword, secureRandomPassword);
     * <p>
     * PBE???????????????????????????????????????????????????????????????????????????????????????????????????????????????
     * ???AES?????????????????????????????????????????????????????????????????????????????????
     * ??????PBE????????????????????????AES??????????????????????????????????????????
     */
    @Test
    public void mainPBEKeySpec() throws Exception {
        // ???BouncyCastle??????Provider?????????java.security:
        //Security.addProvider(new BouncyCastleProvider());
        // ??????:
        String message = "Hello, world!";
        // ????????????:
        String password = "hello12345";
        // 16 bytes??????Salt:
        byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);
        System.out.printf("salt: %032x\n", new BigInteger(1, salt));
        // ??????:
        byte[] data = message.getBytes("UTF-8");
        byte[] encrypted = encrypt(password, salt, data);
        System.out.println("encrypted: " + Base64.encodeBase64String(encrypted));
        // ??????:
        byte[] decrypted = decrypt(password, salt, encrypted);
        System.out.println("decrypted: " + new String(decrypted, "UTF-8"));
    }

    // ??????:
    public static byte[] encrypt(String password, byte[] salt, byte[] input) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory skeyFactory = SecretKeyFactory.getInstance("PBEwithSHA1and128bitAES-CBC-BC");
        SecretKey skey = skeyFactory.generateSecret(keySpec);
        PBEParameterSpec pbeps = new PBEParameterSpec(salt, 1000);
        Cipher cipher = Cipher.getInstance("PBEwithSHA1and128bitAES-CBC-BC");
        cipher.init(Cipher.ENCRYPT_MODE, skey, pbeps);
        return cipher.doFinal(input);
    }

    // ??????:
    public static byte[] decrypt(String password, byte[] salt, byte[] input) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory skeyFactory = SecretKeyFactory.getInstance("PBEwithSHA1and128bitAES-CBC-BC");
        SecretKey skey = skeyFactory.generateSecret(keySpec);
        PBEParameterSpec pbeps = new PBEParameterSpec(salt, 1000);
        Cipher cipher = Cipher.getInstance("PBEwithSHA1and128bitAES-CBC-BC");
        cipher.init(Cipher.DECRYPT_MODE, skey, pbeps);
        return cipher.doFinal(input);
    }

    @Test
    public void signatureSHA1withRSA() throws GeneralSecurityException {
        // ??????RSA??????/??????:
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(2048);
        KeyPair kp = kpGen.generateKeyPair();
        PrivateKey sk = kp.getPrivate();
        PublicKey pk = kp.getPublic();

        // ??????????????????:
        byte[] message = "Hello, I am Bob!".getBytes(StandardCharsets.UTF_8);

        // ???????????????:
        Signature s = Signature.getInstance("SHA1withRSA");
        s.initSign(sk);
        s.update(message);
        byte[] signed = s.sign();
        System.out.println(String.format("signature: %x", new BigInteger(1, signed)));

        // ???????????????:
        Signature v = Signature.getInstance("SHA1withRSA");
        v.initVerify(pk);
        v.update(message);
        boolean valid = v.verify(signed);
        System.out.println("valid? " + valid);
    }


    @Test
    public void signatureSM3withSM2() throws GeneralSecurityException {
        KeyPair kp = SM2Util.generateKeyPair();
        PrivateKey sk = kp.getPrivate();
        PublicKey pk = kp.getPublic();
        byte[] skBytes = sk.getEncoded();
        byte[] pkBytes = pk.getEncoded();
        String skString = Base64.encodeBase64String(skBytes);
        String pkString = Base64.encodeBase64String(pkBytes);
        System.out.println("skString:\n" + skString);
        System.out.println("pkString:\n" + pkString);
        // ??????????????????:
        byte[] message = "Hello, I am Bob!".getBytes(StandardCharsets.UTF_8);
        // ???????????????:
        Signature s = Signature.getInstance("SM3withSM2");
        s.initSign(sk);
        s.update(message);
        byte[] signed = s.sign();
        System.out.println(String.format("signature: %x", new BigInteger(1, signed)));

        // ???????????????:
        Signature v = Signature.getInstance("SM3withSM2");
        v.initVerify(pk);
        v.update(message);
        boolean valid = v.verify(signed);
        System.out.println("valid? " + valid);
    }

    /**
     * ???????????????????????????????????????????????????
     * ?????????????????????????????????????????????????????????CA?????????????????????????????????????????????????????????
     * ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
     * ???????????????????????????????????????CA??????????????????
     * <p>
     * ???Java???????????????????????????????????????Java?????????key store????????????JDK??????????????????????????????????????????key store???
     * ????????????????????????????????????key store??????????????????123456???
     * <p>
     * keytool -storepass 123456 -genkeypair -keyalg RSA -keysize 1024 -sigalg SHA1withRSA
     * -validity 3650 -alias mycert -keystore my.keystore
     * -dname "CN=www.sample.com, OU=sample, O=sample, L=BJ, ST=BJ, C=CN"
     * <p>
     * ???????????????????????????
     * keyalg?????????RSA???????????????
     * sigalg?????????SHA1withRSA???????????????
     * validity????????????????????????3650??????
     * alias?????????????????????????????????????????????
     * dname???????????????CN=www.sample.com?????????Common Name?????????????????????HTTPS????????????????????????????????????????????????
     * ?????????????????????JDK??????????????????????????????my.keystore??????????????????????????????????????????????????????????????????????????????mycert???
     * <p>
     * ??????key store??????????????????????????????????????????????????????????????????????????????
     */
    @Test
    public void mainX509Simple() throws Exception {
        byte[] message = "Hello, use X.509 cert!".getBytes("UTF-8");
        // ??????KeyStore:
        KeyStore ks = loadKeyStore("/my.keystore", "123456");
        // ????????????:
        PrivateKey privateKey = (PrivateKey) ks.getKey("mycert", "123456".toCharArray());
        // ????????????:
        X509Certificate certificate = (X509Certificate) ks.getCertificate("mycert");
        // ??????:
        byte[] encrypted = encrypt(certificate, message);
        System.out.println(String.format("encrypted: %x", new BigInteger(1, encrypted)));
        // ??????:
        byte[] decrypted = decrypt(privateKey, encrypted);
        System.out.println("decrypted: " + new String(decrypted, "UTF-8"));
        // ??????:
        byte[] sign = sign(privateKey, certificate, message);
        System.out.println(String.format("signature: %x", new BigInteger(1, sign)));
        // ????????????:
        boolean verified = verify(certificate, message, sign);
        System.out.println("verify: " + verified);
    }

    static KeyStore loadKeyStore(String keyStoreFile, String password) {
        try (InputStream input = BCTest.class.getResourceAsStream(keyStoreFile)) {
            if (input == null) {
                throw new RuntimeException("file not found in classpath: " + keyStoreFile);
            }
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(input, password.toCharArray());
            return ks;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] encrypt(X509Certificate certificate, byte[] message)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(certificate.getPublicKey().getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());
        return cipher.doFinal(message);
    }

    static byte[] decrypt(PrivateKey privateKey, byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    static byte[] sign(PrivateKey privateKey, X509Certificate certificate, byte[] message)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance(certificate.getSigAlgName());
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    static boolean verify(X509Certificate certificate, byte[] message, byte[] sig)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance(certificate.getSigAlgName());
        signature.initVerify(certificate);
        signature.update(message);
        return signature.verify(sig);
    }
}
