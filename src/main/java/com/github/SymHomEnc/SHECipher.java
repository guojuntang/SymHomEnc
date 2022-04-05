package com.github.SymHomEnc;

import java.math.BigInteger;

public class SHECipher {
    private BigInteger cipher;

    public SHECipher(BigInteger cipher){
        this.cipher = cipher;
    }

    public BigInteger getCipher() {
        return cipher;
    }
}
