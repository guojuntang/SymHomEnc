package com.github.SymHomEnc;

import java.math.BigInteger;

public class SHEPrivateKey {
    private int k0;
    private int k1;
    private int k2;
    private BigInteger N;
    private BigInteger p;
    private BigInteger L;

    public SHEPrivateKey(int k0, int k1, int k2, BigInteger N, BigInteger p, BigInteger L){
        this.k0 = k0;
        this.k1 = k1;
        this.k2 = k2;
        this.N = N;
        this.p = p;
        this.L = L;
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

    public BigInteger getL() {
        return L;
    }

    public BigInteger getN() {
        return N;
    }

    public BigInteger getP() {
        return p;
    }
}
