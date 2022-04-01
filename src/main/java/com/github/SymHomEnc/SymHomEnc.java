package com.github.SymHomEnc;

import java.math.BigInteger;
import java.security.SecureRandom;


public class SymHomEnc {

	final static SecureRandom rnd = new SecureRandom();
	private static int k0;
	private static int k1;
	private static int k2;


	/**
	 * Encrypt BigInteger with private key
	 * @param val
	 * @param sk
	 * @return
	 */
    public static BigInteger enc(BigInteger val, SHEPrivateKey sk) {

    	int k0 = sk.getK0();
    	int k1 = sk.getK1();
    	int k2 = sk.getK2();

    	BigInteger p = sk.getP();
    	BigInteger L = sk.getL();
    	BigInteger N = sk.getN();


		BigInteger r = new BigInteger(k2, rnd);
		BigInteger rp = new BigInteger(k0, rnd);

		return (((r.multiply(L)).add(val)).multiply((BigInteger.ONE).add(rp.multiply(p)))).mod(N);
    }

	/**
	 * Encrypt int with private key
	 * @param val
	 * @param sk
	 * @return
	 */
	public static BigInteger enc(int val, SHEPrivateKey sk){
		BigInteger v = BigInteger.valueOf(val);
		return enc(v, sk);
	}

	/**
	 * Encrypt int with public key
	 * @param val
	 * @param pk
	 * @return
	 */
	public static BigInteger enc(int val, SHEPublicKey pk){
		BigInteger v = BigInteger.valueOf(val);
		return enc(v, pk);
	}


	/**
	 * Encrypt BigInteger with public key
	 * @param val
	 * @param pk
	 * @return
	 */
	public static BigInteger enc(BigInteger val, SHEPublicKey pk){
		int k1 = pk.getK1();
		BigInteger N = pk.getN();
		BigInteger E0_1 = pk.getE0_1();
		BigInteger E0_2 = pk.getE0_2();


		BigInteger r1 = new BigInteger(k1, rnd);
		BigInteger r2 = new BigInteger(k1, rnd);

		// (val + r1*E0_1 + r2*E0_2) mod N
        return val.add(r1.multiply(E0_1)).add(r2.multiply(E0_2)).mod(N);
	}


    public static BigInteger hm_add(BigInteger cipher, BigInteger val, SHEPublicParameter pb){
		BigInteger N = pb.getN();
		// cipher + val mod N
	    return cipher.add(val).mod(N);
	}

	public static BigInteger hm_add(BigInteger cipher, int val, SHEPublicParameter pb){
		BigInteger v = BigInteger.valueOf(val);
		return hm_add(cipher, v, pb);
	}

	public static BigInteger hm_mul(BigInteger cipher, BigInteger val, SHEPublicParameter pb){
		BigInteger N = pb.getN();
		// cipher * val mod N
	    return cipher.multiply(val).mod(N);
	}

	public static BigInteger hm_mul(BigInteger cipher, int val, SHEPublicParameter pb){
		BigInteger v = BigInteger.valueOf(val);
		return hm_mul(cipher, v, pb);
	}

    public static BigInteger dec(BigInteger cipher, SHEPrivateKey sk) {
    	BigInteger p = sk.getP();
    	BigInteger L = sk.getL();

    	// ((cipher mod p) mod L)
        BigInteger result = cipher.mod(p).mod(L);
    	return (result.compareTo(L.divide(BigInteger.valueOf(2))) == -1)? result: result.subtract(L);
    }
    
    
    //public static void main(String[] args) {
	//
	//	// filtration parameters
	//
	//	int filter_k1 = 20;
	//	int filter_k2 = 80;
	//	int filter_k0 = 1024;
	//
	//	SHSParamters filterParam = SymHomEnc.KeyGen(filter_k0, filter_k1, filter_k2);
	//
	//
	//	BigInteger cipherMinusOne = SymHomEnc.EncInt(-1, filterParam);
	//
	//	BigInteger m1 = SymHomEnc.EncInt(1000, filterParam);
	//	BigInteger m2 = SymHomEnc.EncInt(100, filterParam);
	//
	//
	//
	//
	//	BigInteger x = m1.add(m2.multiply(cipherMinusOne));
	//
	//	x = x.add(m2.multiply(cipherMinusOne));
	//
	//	System.out.println(SymHomEnc.Dec(x, filterParam));
	//
    //
	//}
        

    
}
