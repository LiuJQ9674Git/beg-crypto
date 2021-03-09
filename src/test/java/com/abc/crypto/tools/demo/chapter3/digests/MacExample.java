package com.abc.crypto.tools.demo.chapter3.digests;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static com.abc.crypto.tools.demo.chapter3.digests.JceUtils.computeMac;

/**
 * A simple example of using AES CMAC.
 */
public class MacExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecretKey macKey = new SecretKeySpec(
            Hex.decode("dfa66747de9ae63030ca32611497c827"), "AES");

        System.out.println(
            Hex.toHexString(
                computeMac("AESCMAC", macKey,
                                 Strings.toByteArray("Hello World!"))));
    }
}
