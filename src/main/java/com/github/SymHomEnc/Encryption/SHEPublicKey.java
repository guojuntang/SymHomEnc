package com.github.SymHomEnc.Encryption;

import java.math.BigInteger;

public class SHEPublicKey {
    private int k0;
    private int k1;
    private int k2;
    private BigInteger N;
    private BigInteger E0_1;
    private BigInteger E0_2;

    public SHEPublicKey(int k0, int k1, int k2,BigInteger E0_1, BigInteger E0_2, BigInteger N){
        this.k0 = k0;
        this.k1 = k1;
        this.k2 = k2;
        this.E0_1 = E0_1;
        this.E0_2 = E0_2;
        this.N = N;
    }

    public BigInteger getE0_1() {
        return E0_1;
    }

    public BigInteger getE0_2() {
        return E0_2;
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
