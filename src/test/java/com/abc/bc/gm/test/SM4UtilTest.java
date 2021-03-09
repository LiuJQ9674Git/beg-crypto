package com.abc.bc.gm.test;

import com.abc.bc.gm.SM4Util;
import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;


public class SM4UtilTest extends GMBaseTest {

    private final static Logger log = LoggerFactory.getLogger(SM4UtilTest.class);

    public SM4UtilTest() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
    }

    @Test
    public void testEncryptAndDecrypt() {

        //SM4Util.decrypt_String_ECB_NoPadding();
        try {
            String test="中华人民共和国";
            String strKey="7C7982B74091DBC22F17FDA14854EAF0";
            byte[] cipherText = null;
            cipherText = SM4Util.encrypt_ECB_Padding(strKey.getBytes(), test.getBytes());
            String base= new String(Base64.encodeBase64(cipherText));
            //24 0~15        0~4
            //44 16~31       5~8
            //64 32~47       9~15
            //88 48~63       16~21
            //108 64~79      22~25
            //128 80~95      26~31
            //152 96~111     32~40
            //172 112~127    41~43
            //192 128        44~48
            System.out.println("Plan:\t"+test+"\tPlan Lengh:\t"+test.length()+
                    "\tSM4 ECB Padding encrypt result:\n"+
                    "\tBase\t"+base+"\tLength\t"+base.length()+"\t\tstrKey length\t"+strKey.length());

            byte[] decryptedData = null;
            decryptedData = SM4Util.decrypt_ECB_Padding(strKey.getBytes(),
                    Base64.decodeBase64(base.getBytes()));
            String decValue=new String(decryptedData);
            System.out.println("SM4 ECB Padding decrypt result:\t"
                    + decValue+"\tDecryt:\t"+decValue.length());

            log.error("ffffffffff");
//            cipherText = SM4Util.encrypt_CBC_Padding(key, iv, SRC_DATA);
//            System.out.println("SM4 CBC Padding encrypt result:\n" + Arrays.toString(cipherText));
//            decryptedData = SM4Util.decrypt_CBC_Padding(key, iv, cipherText);
//            System.out.println("SM4 CBC Padding decrypt result:\n" + Arrays.toString(decryptedData));
//            if (!Arrays.equals(decryptedData, SRC_DATA)) {
//                Assert.fail();
//            }
//
//            cipherText = SM4Util.encrypt_CBC_NoPadding(key, iv, SRC_DATA_16B);
//            System.out.println("SM4 CBC NoPadding encrypt result:\n" + Arrays.toString(cipherText));
//            decryptedData = SM4Util.decrypt_CBC_NoPadding(key, iv, cipherText);
//            System.out.println("SM4 CBC NoPadding decrypt result:\n" + Arrays.toString(decryptedData));

        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

//    @Test
//    public void testMac() throws Exception {
        byte[] key = SM4Util.generateKey();
        byte[] iv = SM4Util.generateKey();
//
//        byte[] mac = SM4Util.doCMac(key, SRC_DATA_24B);
//        System.out.println("CMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());
//
//        mac = SM4Util.doGMac(key, iv, 16, SRC_DATA_24B);
//        System.out.println("GMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());
//
        byte[] cipher = SM4Util.encrypt_CBC_NoPadding(key, iv, SRC_DATA_32B);
        byte[] cipherLast16 = Arrays.copyOfRange(cipher, cipher.length - 16, cipher.length);
//        mac = SM4Util.doCBCMac(key, iv, null, SRC_DATA_32B);
//        if (!Arrays.equals(cipherLast16, mac)) {
//            Assert.fail();
//        }
//        System.out.println("CBCMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());
//
//        cipher = SM4Util.encrypt_CBC_Padding(key, iv, SRC_DATA_32B);
//        cipherLast16 = Arrays.copyOfRange(cipher, cipher.length - 16, cipher.length);
//        mac = SM4Util.doCBCMac(key, iv, SRC_DATA_32B);
//        if (!Arrays.equals(cipherLast16, mac)) {
//            Assert.fail();
//        }
//        System.out.println("CBCMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());
//    }
}
