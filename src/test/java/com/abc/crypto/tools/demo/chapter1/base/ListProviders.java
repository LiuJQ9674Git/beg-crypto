package com.abc.crypto.tools.demo.chapter1.base;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * Simple application to list installed providers and their available info.
 */
public class ListProviders
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args)
    {
        Provider[] installedProvs = Security.getProviders();

        for (int i = 0; i != installedProvs.length; i++)
        {
            System.out.print(installedProvs[i].getName());
            System.out.print(": ");
            System.out.print(installedProvs[i].getInfo());
            System.out.println();
        }
    }
}
