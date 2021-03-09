package com.abc.crypto.tech.demo.chapter1;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * List the currently installed providers in the Java Runtime
 */
public class ListProviders
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(
        String[]	args)
    {
        Provider[]	providers = Security.getProviders();
        
        for (int i = 0; i != providers.length; i++)
        {
            System.out.println("Name: " + providers[i].getName()
                    + Utils.makeBlankString(15 - providers[i].getName().length())+
                    " Version: " + providers[i].getVersion());
        }
    }
}
