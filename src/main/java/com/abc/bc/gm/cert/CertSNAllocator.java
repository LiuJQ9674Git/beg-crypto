package com.abc.bc.gm.cert;

import java.math.BigInteger;

public interface CertSNAllocator {
    BigInteger nextSerialNumber() throws Exception;
}
