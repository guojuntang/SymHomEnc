package com.github.SymHomEnc.Encryption;

import java.math.BigInteger;

public class SHEPublicParameter {
    private int k0;
    private int k1;
    private int k2;
    private BigInteger N;

    public SHEPublicParameter(int k0, int k1, int k2, BigInteger N){
        this.k0 = k0;
        this.k1 = k1;
        this.k2 = k2;
        this.N = N;
    }

    public int getK0() {
        return k0;
    }

    public int getK1() {
        return k1;
    }

    public int getK2() {
        return k2;
    }

    public BigInteger getN() {
        return N;
    }
}
