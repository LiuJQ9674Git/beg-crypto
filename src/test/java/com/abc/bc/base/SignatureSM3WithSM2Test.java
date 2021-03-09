package com.abc.bc.base;


import com.abc.signature.SignatureSM3WithSM2;
import org.junit.Test;

public class SignatureSM3WithSM2Test {


    @Test
    public void signSM2DSA(){
        SignatureSM3WithSM2 client=new SignatureSM3WithSM2();
        //sign(String keyId, String keyVersionId, String algorithm, byte[] message)
        String keyId="abc";
        String keyVersionId="001";
        String algorithm="SM2DSA";
        byte[] message="Hello".getBytes();
        try {
            client.sign(keyId,keyVersionId,algorithm,message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    @Test
    public void signRSA(){
        SignatureSM3WithSM2 client=new SignatureSM3WithSM2();
        //sign(String keyId, String keyVersionId, String algorithm, byte[] message)
        String keyId="abc";
        String keyVersionId="001";
        String algorithm="SM2DSA";
        byte[] message="Hello".getBytes();
        try {
            client.sign(keyId,keyVersionId,algorithm,message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
