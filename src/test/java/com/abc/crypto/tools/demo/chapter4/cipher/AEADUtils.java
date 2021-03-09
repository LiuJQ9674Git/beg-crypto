package com.abc.crypto.tools.demo.chapter4.cipher;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.util.encoders.Hex;

public class AEADUtils
{
    /**
     * Create a constant value AES key.
     *
     * @return a constant AES key.
     */
    static SecretKey createConstantKey()
    {
        return new SecretKeySpec(
                       Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
    }

    /**
     * Encrypt the passed in data pText using GCM with the passed in parameters.
     *
     * @param key secret key to use.
     * @param iv the IV to use with GCM.
     * @param tagLen the length of the MAC to be generated by GCM.
     * @param pText the plain text input to the cipher.
     * @return the cipher text.
     */
    static byte[] gcmEncrypt(SecretKey key,
                              byte[] iv,
                              int    tagLen,
                              byte[] pText)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        GCMParameterSpec spec = new GCMParameterSpec(tagLen, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        return cipher.doFinal(pText);
    }

    /**
     * Decrypt the cipher text cText using the passed in key and other
     * parameters.
     *
     * @param key secret key to use.
     * @param iv the IV to use with GCM.
     * @param tagLen the length of the MAC previously generated by GCM.
     * @param cText the encrypted cipher text.
     * @return the original plain text.
     */
    static byte[] gcmDecrypt(SecretKey key,
                              byte[] iv,
                              int    tagLen,
                              byte[] cText)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        GCMParameterSpec spec = new GCMParameterSpec(tagLen, iv);

        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(cText);
    }

    /**
     * Encrypt the passed in data pText using GCM with the passed in parameters
     * and incorporating aData into the GCM MAC calculation.
     *
     * @param key secret key to use.
     * @param iv the IV to use with GCM.
     * @param pText the plain text input to the cipher.
     * @param aData the associated data to be included in the GCM MAC.
     * @return the cipher text.
     */
    static byte[] gcmEncryptWithAAD(SecretKey key,
                              byte[] iv,
                              byte[] pText,
                              byte[] aData)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        cipher.updateAAD(aData);

        return cipher.doFinal(pText);
    }

    /**
     * Decrypt the passed in cipher text cText using GCM with the passed in
     * parameters and incorporating aData into the GCM MAC calculation.
     *
     * @param key secret key to use.
     * @param iv the IV originally used with GCM.
     * @param cText the encrypted cipher text.
     * @param aData the associated data to be included in the GCM MAC.
     * @return the plain text.
     */
    static byte[] gcmDecryptWithAAD(SecretKey key,
                              byte[] iv,
                              byte[] cText,
                              byte[] aData)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        AEADParameterSpec spec = new AEADParameterSpec(iv, 128, aData);

        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(cText);
    }

    /**
     * Encrypt the passed in data pText using CCM with the passed in parameters
     * and incorporating aData into the CCM MAC calculation.
     *
     * @param key secret key to use.
     * @param nonce the nonce to use with CCM.
     * @param pText the plain text input to the cipher.
     * @param aData the associated data to process with the plain text.
     * @return the cipher text.
     */
    static byte[] ccmEncryptWithAAD(SecretKey key,
                              byte[] nonce,
                              byte[] pText,
                              byte[] aData)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");

        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);

        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        cipher.updateAAD(aData);

        return cipher.doFinal(pText);
    }

    /**
      * Decrypt the passed in cipher text cText using CCM with the passed in
      * parameters and incorporating aData into the CCM MAC calculation.
      *
      * @param key secret key to use.
      * @param nonce the nonce originally used with CCM.
      * @param cText the encrypted cipher text.
      * @param aData the associated data to be included in the CCM MAC.
      * @return the plain text.
      */
    static byte[] ccmDecryptWithAAD(SecretKey key,
                              byte[] nonce,
                              byte[] cText,
                              byte[] aData)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");

        AEADParameterSpec spec = new AEADParameterSpec(nonce, 128, aData);

        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(cText);
    }

    /**
     * Encrypt the passed in data pText using EAX mode with the passed in
     * parameters.
     *
     * @param key secret key to use.
     * @param nonce the nonce to use with the EAX mode.
     * @param pText the plain text input to the cipher.
     * @return the cipher text.
     */
    static byte[] eaxEncrypt(SecretKey key,
                              byte[] nonce,
                              byte[] pText)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/EAX/NoPadding", "BC");

        AEADParameterSpec spec = new AEADParameterSpec(nonce, 128);
        
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        return cipher.doFinal(pText);
    }

    /**
     * Decrypt the cipher text cText using the passed in key and other
     * parameters using EAX mode.
     *
     * @param key secret key to use.
     * @param nonce the nonce to use with EAX.
     * @param cText the encrypted cipher text.
     * @return the original plain text.
     */
    static byte[] eaxDecrypt(SecretKey key,
                              byte[] nonce,
                              byte[] cText)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/EAX/NoPadding", "BC");

        AEADParameterSpec spec = new AEADParameterSpec(nonce, 128);

        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(cText);
    }
}