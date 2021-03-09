package com.abc.bc.base;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/**
 * 要解决这个问题，密钥交换算法即DH算法：Diffie-Hellman算法应运而生。
 *
 * DH算法解决了密钥在双方不直接传递密钥的情况下完成密钥交换，这个神奇的交换原理完全由数学理论支持。
 *
 * 我们来看DH算法交换密钥的步骤。假设甲乙双方需要传递密钥，他们之间可以这么做：
 *
 * 甲首选选择一个素数p，例如509，底数g，任选，例如5，随机数a，例如123，然后计算A=g^a mod p，结果是215，然后，甲发送p＝509，g=5，A=215给乙；
 * 乙方收到后，也选择一个随机数b，例如，456，然后计算B=g^b mod p，结果是181，乙再同时计算s=A^b mod p，结果是121；
 * 乙把计算的B=181发给甲，甲计算s＝B^a mod p的余数，计算结果与乙算出的结果一样，都是121。
 * 所以最终双方协商出的密钥s是121。注意到这个密钥s并没有在网络上传输。而通过网络传输的p，g，A和B是无法推算出s的，因为实际算法选择的素数是非常大的。
 *
 * 所以，更确切地说，DH算法是一个密钥协商算法，双方最终协商出一个共同的密钥，而这个密钥不会通过网络传输。
 *
 * 如果我们把a看成甲的私钥，A看成甲的公钥，b看成乙的私钥，B看成乙的公钥，
 * DH算法的本质就是双方各自生成自己的私钥和公钥，私钥仅对自己可见，然后交换公钥，
 * 并根据自己的私钥和对方的公钥，生成最终的密钥secretKey，DH算法通过数学定律保证了双方各自计算出的secretKey是相同的。
 */
public class KeyAgreementTest {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args) {
        // Bob和Alice:
        Person bob = new Person("Bob");
        Person alice = new Person("Alice");

        // 各自生成KeyPair:
        bob.generateKeyPair();
        alice.generateKeyPair();

        // 双方交换各自的PublicKey:
        // Bob根据Alice的PublicKey生成自己的本地密钥:
        bob.generateSecretKey(alice.publicKey.getEncoded());
        // Alice根据Bob的PublicKey生成自己的本地密钥:
        alice.generateSecretKey(bob.publicKey.getEncoded());

        // 检查双方的本地密钥是否相同:
        bob.printKeys();
        alice.printKeys();
        // 双方的SecretKey相同，后续通信将使用SecretKey作为密钥进行AES加解密...
    }
    static  class Person {
        public final String name;

        public PublicKey publicKey;
        private PrivateKey privateKey;
        private byte[] secretKey;

        public Person(String name) {
            this.name = name;
        }

        // 生成本地KeyPair:
        public void generateKeyPair() {
            try {
                KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DH");
                kpGen.initialize(512);
                KeyPair kp = kpGen.generateKeyPair();
                this.privateKey = kp.getPrivate();
                this.publicKey = kp.getPublic();
            } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        }

        public void generateSecretKey(byte[] receivedPubKeyBytes) {
            try {
                // 从byte[]恢复PublicKey:
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receivedPubKeyBytes);
                KeyFactory kf = KeyFactory.getInstance("DH");
                PublicKey receivedPublicKey = kf.generatePublic(keySpec);
                // 生成本地密钥:
                KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
                keyAgreement.init(this.privateKey); // 自己的PrivateKey
                keyAgreement.doPhase(receivedPublicKey, true); // 对方的PublicKey
                // 生成SecretKey密钥:
                this.secretKey = keyAgreement.generateSecret();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public void printKeys() {
            System.out.printf("Name: %s\n", this.name);
            System.out.printf("Private key: %x\n", new BigInteger(1, this.privateKey.getEncoded()));
            System.out.printf("Public key: %x\n", new BigInteger(1, this.publicKey.getEncoded()));
            System.out.printf("Secret key: %x\n", new BigInteger(1, this.secretKey));
        }
    }
}



