package com.SymHomEnc;

import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class SymHomEncTest {
    @Test
    public void paramCheck(){
        SHEParameters param = new SHEParameters(SHEParameters.K0, SHEParameters.K1, SHEParameters.K2);
        SHEPrivateKey sk = param.getSHEPrivateKey();
        SHEPublicKey pk = param.getSHEPublicKey();
        SHEPublicParameter pb = param.getSHEPublicParameter();

        assertEquals(pb.getK0(), SHEParameters.K0);
        assertEquals(pb.getK1(), SHEParameters.K1);
        assertEquals(pb.getK2(), SHEParameters.K2);

        assertEquals(pk.getK0(), SHEParameters.K0);
        assertEquals(pk.getK1(), SHEParameters.K1);
        assertEquals(pk.getK2(), SHEParameters.K2);

        assertEquals(sk.getK0(), SHEParameters.K0);
        assertEquals(sk.getK1(), SHEParameters.K1);
        assertEquals(sk.getK2(), SHEParameters.K2);

    }

    @Test
    public void encDecTest(){
        SHEParameters param = new SHEParameters(SHEParameters.K0, SHEParameters.K1, SHEParameters.K2);
        SHEPrivateKey sk = param.getSHEPrivateKey();

        BigInteger a = SymHomEnc.enc(123456, sk);
        BigInteger b = SymHomEnc.dec(a, sk);

        assertEquals(b, BigInteger.valueOf(123456));


        BigInteger c = SymHomEnc.enc(-4401, sk);
        BigInteger d = SymHomEnc.dec(c, sk);

        assertEquals(d, BigInteger.valueOf(-4401));
    }

    @Test
    public void publicKeyTest(){
        SHEParameters param = new SHEParameters(SHEParameters.K0, SHEParameters.K1, SHEParameters.K2);
        SHEPublicKey pk = param.getSHEPublicKey();
        SHEPrivateKey sk = param.getSHEPrivateKey();

        assertEquals(SymHomEnc.dec(pk.getE0_1(), sk), BigInteger.ZERO);
        assertEquals(SymHomEnc.dec(pk.getE0_2(), sk), BigInteger.ZERO);

        BigInteger a = SymHomEnc.enc(1234456, pk);
        BigInteger b = SymHomEnc.dec(a, sk);

        assertEquals(b, BigInteger.valueOf(1234456));

        BigInteger c = SymHomEnc.enc(-4401, pk);
        BigInteger d = SymHomEnc.dec(c, sk);

        assertEquals(d, BigInteger.valueOf(-4401));
    }

    @Test
    public void homoTest(){
        SHEParameters param = new SHEParameters(SHEParameters.K0, SHEParameters.K1, SHEParameters.K2);
        SHEPrivateKey sk = param.getSHEPrivateKey();

        SHEPublicParameter pb = param.getSHEPublicParameter();
        SHEPublicKey pk = param.getSHEPublicKey();

        // a0 + 3
        BigInteger a0 = SymHomEnc.enc(12, pk);
        BigInteger b0 = SymHomEnc.hm_add(a0, 3, pb);
        assertEquals(SymHomEnc.dec(b0, sk), BigInteger.valueOf(15));

        // a1 + 3
        BigInteger a1 = SymHomEnc.enc(-12, pk);
        BigInteger b1 = SymHomEnc.hm_add(a1, 3, pb);
        assertEquals(SymHomEnc.dec(b1, sk), BigInteger.valueOf(-9));

        // a1 * a1
        BigInteger a2 = SymHomEnc.hm_mul(a1, a1, pb);
        assertEquals(SymHomEnc.dec(a2, sk), BigInteger.valueOf(144));


        //-a2 + a0
        BigInteger a3 = SymHomEnc.enc(-1, sk);
        BigInteger b2 = SymHomEnc.hm_mul(a2, a3, pb);
        BigInteger b3 = SymHomEnc.hm_add(b2, a0, pb);
        assertEquals(SymHomEnc.dec(b3,sk), BigInteger.valueOf(-132));

        // a1 * 100
        BigInteger b4 = SymHomEnc.hm_mul(a2, 100, pb);
        assertEquals(SymHomEnc.dec(b4, sk), BigInteger.valueOf(14400));

    }
}
