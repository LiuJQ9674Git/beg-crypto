package com.abc.signature;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;

public class RsaUtils
{
    /**
     * Generate a 2048 bit RSA key pair using user specified parameters.
     *
     * @return a RSA KeyPair
     */
    public static KeyPair generateRSAKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BC");

        keyPair.initialize(
            new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));

        return keyPair.generateKeyPair();
    }
    /**
     * Generate an encoded RSA signature using the passed in private key and
     * input data.
     * 
     * @param rsaPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generatePKCS1dot5Signature(
        PrivateKey rsaPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");

        signature.initSign(rsaPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in signature verifies against
     * the passed in RSA public key and input.
     *
     * @param rsaPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyPKCS1dot5Signature(
        PublicKey rsaPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");

        signature.initVerify(rsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }
    /**
     * Generate an encoded RSA signature using the passed in private key and
     * input data.
     * 
     * @param rsaPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateRSAPSSSignature(
        PrivateKey rsaPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withRSAandMGF1", "BC");

        signature.initSign(rsaPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in signature verifies against
     * the passed in RSA public key and input.
     *
     * @param rsaPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyRSAPSSSignature(
        PublicKey rsaPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withRSAandMGF1", "BC");

        signature.initVerify(rsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }
    /**
     * Generate an encoded RSA signature using the passed in private key and
     * input data.
     * 
     * @param rsaPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateRSAPSSSignature(
        PrivateKey rsaPrivate, PSSParameterSpec pssSpec, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("RSAPSS", "BC");

        signature.setParameter(pssSpec);

        signature.initSign(rsaPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in signature verifies against
     * the passed in RSA public key and input.
     *
     * @param rsaPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyRSAPSSSignature(
        PublicKey rsaPublic, PSSParameterSpec pssSpec,
        byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("RSAPSS", "BC");

        signature.setParameter(pssSpec);

        signature.initVerify(rsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }

    /**
     * Generate a wrapped key using the RSA OAEP algorithm,
     * returning the resulting encryption.
     *
     * @param rsaPublic the public key to base the wrapping on.
     * @param secretKey the secret key to be encrypted/wrapped.
     * @return true if the signature verifies, false otherwise.
     */
    public static byte[] keyWrapOAEP(
            PublicKey rsaPublic, SecretKey secretKey)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance(
                "RSA/NONE/OAEPwithSHA256andMGF1Padding", "BC");

        cipher.init(Cipher.WRAP_MODE, rsaPublic);

        return cipher.wrap(secretKey);
    }
    /**
     * Return the secret key that was encrypted in wrappedKey.
     *
     * @param rsaPrivate the private key to use for the unwrap.
     * @param wrappedKey the encrypted secret key.
     * @param keyAlgorithm the algorithm that the encrypted key is for.
     * @return the unwrapped SecretKey.
     */
    public static SecretKey keyUnwrapOAEP(
            PrivateKey rsaPrivate, byte[] wrappedKey, String keyAlgorithm)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance(
                "RSA/NONE/OAEPwithSHA256andMGF1Padding", "BC");

        cipher.init(Cipher.UNWRAP_MODE, rsaPrivate);

        return (SecretKey)cipher.unwrap(
                wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }
    /**
     * Generate a wrapped key using the RSA OAEP algorithm according
     * to the passed in OAEPParameterSpec and return the resulting encryption.
     *
     * @param rsaPublic the public key to base the wrapping on.
     * @param oaepSpec the parameter specification for the OAEP operation.
     * @param secretKey the secret key to be encrypted/wrapped.
     * @return true if the signature verifies, false otherwise.
     */
    public static byte[] keyWrapOAEP(
            PublicKey rsaPublic, OAEPParameterSpec oaepSpec, SecretKey secretKey)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("RSA", "BC");

        cipher.init(Cipher.WRAP_MODE, rsaPublic, oaepSpec);

        return cipher.wrap(secretKey);
    }
    /**
     * Return the secret key that was encrypted in wrappedKey.
     *
     * @param rsaPrivate the private key to use for the unwrap.
     * @param oaepSpec the parameter specification for the OAEP operation.
     * @param wrappedKey the encrypted secret key.
     * @param keyAlgorithm the algorithm that the encrypted key is for.
     * @return the unwrapped SecretKey.
     */
    public static SecretKey keyUnwrapOAEP(
            PrivateKey rsaPrivate, OAEPParameterSpec oaepSpec,
            byte[] wrappedKey, String keyAlgorithm)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("RSA", "BC");

        cipher.init(Cipher.UNWRAP_MODE, rsaPrivate, oaepSpec);

        return (SecretKey)cipher.unwrap(
                wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }
}
