package com.abc.crypto.tools.demo.chapter3.digests;

import java.io.OutputStream;

import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static com.abc.crypto.tools.demo.chapter3.digests.JcaUtils.createDigestCalculator;

/**
 * Creation and use of a SHA-256 DigestCalculator.
 */
public class DigestCalculatorExample
{
    public static void main(String[] args)
        throws Exception
    {
        DigestCalculator digCalc = createDigestCalculator("SHA-256");

        OutputStream dOut = digCalc.getOutputStream();

        dOut.write(Strings.toByteArray("Hello World!"));

        dOut.close();

        System.out.println(Hex.toHexString(digCalc.getDigest()));
    }
}
