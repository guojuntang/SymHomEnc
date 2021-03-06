package com.github.SymHomEnc;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class SHEParameters {
	
	public static final int K0 = 1024;
	public static final int K1 = 30;
	public static final int K2 = 80;

	private Random rnd;

	/**
	 *  Length of large prime numbers p and q
	 */
	private int k0;
	/**
	 * Length of message and message space
	 */
	private int k1;
	/**
	 * Length of parameter L and generated random values in encryption method
	 */
	private int k2;


	private BigInteger p;
	private BigInteger q;
	private BigInteger N;
	private BigInteger L;
	
	public SHEParameters(int k0, int k1, int k2) {
		this.k0 = k0;
		this.k1 = k1;
		this.k2 = k2;
		this.rnd = new SecureRandom();
		keyGenHelper();
	}

	public SHEParameters(int k0, int k1, int k2, Random rnd) {
		this.k0 = k0;
		this.k1 = k1;
		this.k2 = k2;
		this.rnd = rnd;
		keyGenHelper();
	}


	private void keyGenHelper()
	{
		p = new BigInteger(k0, 40, rnd); // Certainty = 40
		q = new BigInteger(k0, 40, rnd); // Certainty = 40
		N = p.multiply(q);
		L = new BigInteger(k2, rnd); //L in {1,2,3,..., 2^k2}; e.g., k2=80;
	}

	public SHEPublicParameter getSHEPublicParameter(){
	    SHEPublicParameter pb = new SHEPublicParameter(k0, k1, k2, N);
	    return pb;
	}

	public SHEPrivateKey getSHEPrivateKey(){
	    SHEPrivateKey sk = new SHEPrivateKey(k0, k1, k2, N, p, L);
	    return sk;
	}

	public SHEPublicKey getSHEPublicKey(){

		BigInteger r1 = new BigInteger(k2, rnd);
		BigInteger r2 = new BigInteger(k2, rnd);
		BigInteger rp1 = (new BigInteger(k0, rnd));
		BigInteger rp2 = (new BigInteger(k0, rnd));

		SHECipher E0_1 = new SHECipher((((r1.multiply(L)).add(BigInteger.ZERO)).multiply((BigInteger.ONE).add(rp1.multiply(p)))).mod(N));
		SHECipher E0_2 = new SHECipher((((r2.multiply(L)).add(BigInteger.ZERO)).multiply((BigInteger.ONE).add(rp2.multiply(p)))).mod(N));

		SHEPublicKey pk = new SHEPublicKey(k0, k1, k2,E0_1, E0_2,N);

		return pk;
	}
}
