//package com.abc.crypto.tools.demo.chapter7.certificates;
//
//import java.security.GeneralSecurityException;
//import java.security.KeyPair;
//import java.security.Security;
//import java.security.spec.MGF1ParameterSpec;
//
//import javax.crypto.SecretKey;
//import javax.crypto.spec.OAEPParameterSpec;
//import javax.crypto.spec.PSource;
//
//import com.abc.signature.RsaUtils;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.util.Arrays;
//import org.bouncycastle.util.Strings;
//
////import static com.abc.signature.RsaUtils.generateRSAKeyPair;
//import static com.abc.crypto.tools.demo.chapter7.certificates.Utils.createTestAESKey;
//
///**
// * Simple example showing secret key wrapping and unwrapping based on OAEP
// * and using the OAEPParameterSpec class to configure the encryption.
// */
//public class OAEPParamsExample
//{
//    static {
//        Security.addProvider(new BouncyCastleProvider());
//    }
//    public static void main(String[] args)
//        throws GeneralSecurityException
//    {
//        SecretKey aesKey = createTestAESKey();
//
//        KeyPair kp = RsaUtils.generateRSAKeyPair();
//        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
//                                        "SHA-256",
//                                        "MGF1", MGF1ParameterSpec.SHA256,
//                                            new PSource.PSpecified(
//                                              Strings.toByteArray("My Label")));
//
//        byte[] wrappedKey = RsaUtils.keyWrapOAEP(kp.getPublic(), aesKey);
//
//        SecretKey recoveredKey = RsaUtils.keyUnwrapOAEP(
//                                    kp.getPrivate(), oaepSpec,
//                                    wrappedKey, aesKey.getAlgorithm());
//
//        System.out.println(
//            Arrays.areEqual(aesKey.getEncoded(), recoveredKey.getEncoded()));
//    }
//}
