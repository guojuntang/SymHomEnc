package com.github.SymHomEnc;

import java.math.BigInteger;
import java.security.SecureRandom;


public class SymHomEnc {

	final static SecureRandom rnd = new SecureRandom();


	//TODO: define SHE plaintext

	/**
	 * Encrypt BigInteger with private key
	 * @param val
	 * @param sk
	 * @return
	 */

	public static SHECipher enc(int val, SHEPrivateKey sk){
		BigInteger v = BigInteger.valueOf(val);
		return enc(v, sk);
	}

	/**
	 * Encrypt int with private key
	 * @param val
	 * @param sk
	 * @return
	 */
	public static SHECipher enc(BigInteger val, SHEPrivateKey sk) throws RuntimeException {
		int k0 = sk.getK0();
		int k1 = sk.getK1();
		int k2 = sk.getK2();

		if (val.bitLength() > k1){
			throw new RuntimeException("SHE plaintext is out of range");
		}

		BigInteger p = sk.getP();
		BigInteger L = sk.getL();
		BigInteger N = sk.getN();


		BigInteger r = new BigInteger(k2, rnd);
		BigInteger rp = new BigInteger(k0, rnd);

		BigInteger result =  (((r.multiply(L)).add(val)).multiply((BigInteger.ONE).add(rp.multiply(p)))).mod(N);
		return new SHECipher(result);
    }


	/**
	 * Encrypt int with public key
	 * @param val
	 * @param pk
	 * @return
	 */
	public static SHECipher enc(int val, SHEPublicKey pk){
		BigInteger v = BigInteger.valueOf(val);
		return enc(v, pk);
	}


	/**
	 * Encrypt BigInteger with public key
	 * @param val
	 * @param pk
	 * @return
	 */
	public static SHECipher enc(BigInteger val, SHEPublicKey pk){
		try {
			return enc_helper(val, pk);
		}catch (Exception e){
			e.printStackTrace();
			return null;
		}
	}

	private static SHECipher enc_helper(BigInteger val, SHEPublicKey pk) throws Exception {
		int k1 = pk.getK1();

		if (val.bitLength() > k1) {
			throw new Exception("SHE plaintext is out of range");
		}

		BigInteger N = pk.getN();
		SHECipher E0_1 = pk.getE0_1();
		SHECipher E0_2 = pk.getE0_2();


		BigInteger r1 = new BigInteger(k1, rnd);
		BigInteger r2 = new BigInteger(k1, rnd);

		SHEPublicParameter pb = pk.getPublicParameter();

		// (val + r1*E0_1 + r2*E0_2) mod N

		//BigInteger result = val.add(r1.multiply(E0_1)).add(r2.multiply(E0_2)).mod(N);
		// return new SHECipher(result);
        SHECipher v =new SHECipher(val);

		return hm_add(v, hm_add(hm_mul(E0_1, r1,pb),hm_mul(E0_2, r2, pb), pb), pb);

	}

	/**
	 * Homomorphic add 1
	 * @param cipher
	 * @param val
	 * @param pb
	 * @return
	 */
	public static SHECipher hm_add(SHECipher cipher, SHECipher val, SHEPublicParameter pb){
	    BigInteger v = val.getCipher();
	    return hm_add(cipher, v, pb);
	}

	/**
	 * Homomorphic add 2
	 * @param cipher
	 * @param val
	 * @param pb
	 * @return
	 */
    public static SHECipher hm_add(SHECipher cipher, BigInteger val, SHEPublicParameter pb){
		BigInteger N = pb.getN();
		// cipher + val mod N
		BigInteger v = cipher.getCipher().add(val).mod(N);
		return new SHECipher(v);
	}

	/**
	 * Homomorphic add 2
	 * @param cipher
	 * @param val
	 * @param pb
	 * @return
	 */
	public static SHECipher hm_add(SHECipher cipher, int val, SHEPublicParameter pb){
		BigInteger v = BigInteger.valueOf(val);
		return hm_add(cipher, v, pb);
	}


	/**
	 * Homomorphic mul 2
	 * @param cipher
	 * @param val
	 * @param pb
	 * @return
	 */
	public static SHECipher hm_mul(SHECipher cipher, BigInteger val, SHEPublicParameter pb) throws RuntimeException{
		BigInteger N = pb.getN();
		if(val.compareTo(BigInteger.ZERO) != 1){
		    throw new RuntimeException("SHE Homomorphic mul: val must be non-negetive");
		}
		// cipher * val mod N
	    return new SHECipher(cipher.getCipher().multiply(val).mod(N));
	}

	/**
	 * Homomorphic mul 2
	 * @param cipher
	 * @param val
	 * @param pb
	 * @return
	 */
	public static SHECipher hm_mul(SHECipher cipher, int val, SHEPublicParameter pb){
		BigInteger v = BigInteger.valueOf(val);
		return hm_mul(cipher, v, pb);
	}

	public static SHECipher hm_mul(SHECipher cipher, SHECipher val, SHEPublicParameter pb){
	    BigInteger v = val.getCipher();
	    return hm_mul(cipher, v, pb);
	}

    public static BigInteger dec(SHECipher cipher, SHEPrivateKey sk) {
    	BigInteger p = sk.getP();
    	BigInteger L = sk.getL();

    	// ((cipher mod p) mod L)
        BigInteger result = cipher.getCipher().mod(p).mod(L);
    	return (result.compareTo(L.divide(BigInteger.valueOf(2))) == -1)? result: result.subtract(L);
    }
    
    

}
