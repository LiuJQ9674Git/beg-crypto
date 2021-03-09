package com.abc.bc.gm.test;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;
//import org.zz.gmhelper.cert.test.FileSNAllocatorTest;
import com.abc.bc.gm.cert.SM2CertUtilTest;
import com.abc.bc.gm.cert.SM2PfxMakerTest;
import com.abc.bc.gm.cert.SM2PrivateKeyTest;

@RunWith(Suite.class)
@SuiteClasses({BCECUtilTest.class, SM2UtilTest.class, SM3UtilTest.class, SM4UtilTest.class,
    SM2KeyExchangeUtilTest.class, SM2PreprocessSignerTest.class,
    // ------------------------------------
    //FileSNAllocatorTest.class,
        SM2CertUtilTest.class, SM2PfxMakerTest.class, SM2PrivateKeyTest.class})
public class AllTest {
}
