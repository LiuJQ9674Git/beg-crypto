package com.abc.bc.gm;

import sun.misc.BASE64Decoder;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 加签验签,私钥加签,公钥验签
 * 加密解密,公钥加密,私钥解密
 * 2019年7月29日13:43:25
 * @author ful
 *
 */
public class RSAUtil {

    //加签验签的公钥
    private static String PUBLIC_KEY ="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4L/7MhR99+yswtvSr0dKen";
    public static final String KEY_ALGORITHM = "RSA";

    public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

    //加密解密的公钥
    private static String PUBLIC_KEY2 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCLL3buJCUeWdIXufBUSthNVdR6f5wZXlm/GSNKHOG=";

    //加密解密的私钥
    private static String PRIVATE_KEY2 = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIsvdu4kJR5Z0he58FRK2E1V1Hp/nBleWb8ZI0IZTaX5hqwbKmEkFaocswUoc4bzoHXwSNHVek8UjpNuYG7PCRmNIL2bVaXOvsv8EFAQ67mk17+aSPhHNETajRgjE7nJvZSsdLEa2fmtBHBxzNOEUT/f4wfnZ3AJ/vju/3nX9a21AgMBAAECgYB55VPPNDCd6CQrS1jDOdk9wZGYxvG69fq7dhR+6xIp7eKYECKJeMTQetn+BnNHGU7Ke2oK+19mqqZDUEN8SC26vCqpgw8cmFgqTMCYc4i7wnQaOlE20X/sonFZNz4plEIe3SQbQeBlgr/sl80QPgsAnTMFWCCZ1yX1FbSyjs4ucQJBAMJ1qRwoiO9yMUUzNEBWNar6JU4TXybG0sMimUFe6SMAzct5wR0IDD+V4O+ps1Rwu51v8ltes80/+3BFvUBiHTMCQQC3O7WTPpk1V8LRE7bn3Hjh8QdLkdAi13cKaz8Y+vraLJuiuEgnFnUTfTqRmRJ4p1ejb0XPhI+HaVEd+985P3l3AkEAi7roTWeDHiu747Grdh98aONeMwAQe1ia0cTmwuZkN9a4CeHvNeE2i+oyu4QBbEelSLfMOoOOR4oWLtKt7rmRqQJASPHCRU4EXBIGAongpMlGblwv1UvFGjnAsCslwWIY/0YG526JetYb4ZhW+qN/kPy9jNi9Z/GT2gp5OoCMyxOT3QJBAKEduCHZpY5Jre5i9s7tWm94WO7UAAxi9f93aXHuf7DKgZ8psX+/FQd59jTcajWJX9NN/aTjlRNaapLzayGvdWk=";

    /**
     * 验证签名
     *
     * @param signString
     * @param sign
     * @return
     * @throws Exception
     */
    public static boolean verify(String signString, String sign) throws Exception {

        byte[] data = decryptBASE64(signString);

        byte[] signs = sign.getBytes();

        try {
            //实例化
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            // 解密由base64编码的公钥
            byte[] keyBytes = decryptBASE64(PUBLIC_KEY);

            // 构造X509EncodedKeySpec对象
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

            // KEY_ALGORITHM 指定的加密算法
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

            // 取公钥对象
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            //初始化
            signature.initVerify(pubKey);

            //更新
            signature.update(signs);

            //验签
            return signature.verify(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return false;
    }

    /**
     * 加密数据
     * @param originData
     * @return
     */
    public static String encodeData(String originData){
        try {
            // 取公钥对象
            PublicKey pubKey = getPublicKey(PUBLIC_KEY2);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,pubKey);
            byte[] bytesEncrypt = cipher.doFinal(originData.getBytes());
            //Base64编码
            byte[] bytesEncryptBase64 = Base64.getEncoder().encode(bytesEncrypt);
            return new String(bytesEncryptBase64);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密数据
     * @param encodeData
     * @return
     */
    public static String decodeData(String encodeData){
        try {

            // 取公钥对象
            PrivateKey privateKey = getPrivateKey(PRIVATE_KEY2);

            //Base64解码
            byte[] bytesEncrypt = Base64.getDecoder().decode(encodeData);
            //加密
            Cipher cipher = Cipher.getInstance("RSA");

            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            byte[] bytesDecrypt = cipher.doFinal(bytesEncrypt);
            return new String(bytesDecrypt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * BASE64解密
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptBASE64(String key) throws Exception {
        return (new BASE64Decoder()).decodeBuffer(key);
    }

    /**
     * 将字符串转换成公钥
     * @param key
     * @return
     * @throws Exception
     */
    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 将字符串转换成私钥
     * @param key
     * @return
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }



    public static void main(String[] args) {
        /**
         * 私钥加签
         * 公钥验签
         */
        try {
            String signString = "YBBNqO5nTbuNLAwm4vMkLb/h7CDDTBDuOFgXaui/2UtLl8iwXYdj/LQKvpwpdYTzawfawiidWMzMeFri4753WvlVegk5CKx9CHqo4NbAmI62c+P9yv6rZ398V/Q2NJOeM7XV+0602lbozbh2UrYIpciH14hnQ1UfJthIdRB07Y8=";
            String sign = "memberid=1232&changAmount=123&changeWay=1";
            boolean flag = verify(signString,sign);
            System.out.println("验证结果:"+flag);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
