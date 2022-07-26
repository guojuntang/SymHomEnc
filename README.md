Symmetric Homomorphic Encryption
-------------
Symmetric Homomorphic Encryption (SHE) is a Somewhat Homomorphic Encryption that supports both homomorphic addition and homomorphic multiplication.


Homomorphic Properties
--------

**Homomorphic Addition-1**: Two ciphertexts E(m1) and E(m2) satisfy E(m1) + E(m2) mod N -> E(m1+m2)

**Homomorphic Multiplication-1**: Two ciphertexts E(m1) and E(m2) satisfy E(m1) * E(m2) mod N -> E(m1*m2)

**Homomorphic Addition-2**: A ciphertext E(m1) and a plaintext message m2 satisfy E(m1) + m2 mod N -> E(m1+m2)

**Homomorphic Multiplication-2**: A ciphertext E(m1) and a plaintext message m2 > 0 satisfy E(m1) * m2 mod N -> E(m1 * m2)

Maximum Multiplicative Depth
------
SHE can support unlimited rounds of homomorphic addition-1,2, and homomorphic multiplication-2, but it can only provide a limited depth of homomorphic multiplication-1. Usually, we set up the maximum depth as (k0 /k2 - 1), where k0 and k2 are security parameters of the encryption algorithm. The ciphertext will be decrypted incorrectly if it exceeds the maximum depth.

Getting Start
-----

Temporally, this repo is not available at Maven Central. You can download [package](https://github.com/guojuntang/SymHomEnc/packages/) and add the dependency locally.

Maven example:
```
        <dependency>
            <groupId>guojuntang-github</groupId>
            <artifactId>symhomenc</artifactId>
            <version>0.4</version>
            <scope>system</scope>
            <systemPath>${project.basedir}/lib/symhomenc.jar</systemPath>
        </dependency>

```

Usage
-----

### Initialization
Set up the SHE security parameters(k0 >> k2 > k1, see the reference for details.) and require the private key, public key, and public parameter.

```java
        // Using the SecureRandom class as the default random number generator
        SHEParameters param = new SHEParameters(SHEParameters.K0, SHEParameters.K1, SHEParameters.K2);
        SHEPrivateKey sk = param.getSHEPrivateKey();
        SHEPublicKey pk = param.getSHEPublicKey();
        SHEPublicParameter pb = param.getSHEPublicParameter();
```
Also, you can also use the other Random class as the random number generator.
```java 
        Random random = new Random();
        SHEParameters parameters = new SHEParameters(SHEParameters.K0, SHEParameters.K1, SHEParameters.K2, random);
```

### Encryption and Decryption

```java
        // Encryption with private key
        SHECipher a = SymHomEnc.enc(123456, sk);
        // Encryption with public key
        SHECipher b = SymHomEnc.enc(123456, pk);
        // Decryption with private key
        BigInteger c = SymHomEnc.dec(a, sk);
```
Also, you can also use the other Random class as the random number generator.
```java
        Random random = new Random();
        SHECipher a = SymHomEnc.enc(123456, sk, random);
```

### Homomorphic properties

```java
// a0 + 3
        SHECipher a0 = SymHomEnc.enc(12, pk);
                SHECipher b0 = SymHomEnc.hm_add(a0, 3, pb);
                assertEquals(SymHomEnc.dec(b0, sk), BigInteger.valueOf(15));

                // a1 + 3
                SHECipher a1 = SymHomEnc.enc(-12, pk);
                SHECipher b1 = SymHomEnc.hm_add(a1, 3, pb);
                assertEquals(SymHomEnc.dec(b1, sk), BigInteger.valueOf(-9));

                // a1 * a1
                SHECipher a2 = SymHomEnc.hm_mul(a1, a1, pb);
                assertEquals(SymHomEnc.dec(a2, sk), BigInteger.valueOf(144));


                //-a2 + a0
                SHECipher a3 = SymHomEnc.enc(-1, sk);
                SHECipher b2 = SymHomEnc.hm_mul(a2, a3, pb);
                SHECipher b3 = SymHomEnc.hm_add(b2, a0, pb);
                assertEquals(SymHomEnc.dec(b3,sk), BigInteger.valueOf(-132));

                // a1 * 100
                SHECipher b4 = SymHomEnc.hm_mul(a2, 100, pb);
                assertEquals(SymHomEnc.dec(b4, sk), BigInteger.valueOf(14400));

```


Reference
-----------
H. Mahdikhani, R. Lu, Y. Zheng, J. Shao and A. A. Ghorbani, "Achieving O(log³n) Communication-Efficient Privacy-Preserving Range Query in Fog-Based IoT," in IEEE Internet of Things Journal, vol. 7, no. 6, pp. 5220-5232, June 2020, doi: 10.1109/JIOT.2020.2977253.