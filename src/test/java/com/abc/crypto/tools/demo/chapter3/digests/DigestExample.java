package com.abc.crypto.tools.demo.chapter3.digests;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static com.abc.crypto.tools.demo.chapter3.digests.JcaUtils.computeDigest;

/**
 * A simple example of using a MessageDigest.
 */
public class DigestExample
{
    public static void main(String[] args)
        throws Exception
    {
        System.out.println(
            Hex.toHexString(
                computeDigest("SHA-256", Strings.toByteArray("Hello World!"))));
    }
}
