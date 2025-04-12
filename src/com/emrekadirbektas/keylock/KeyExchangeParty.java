package com.emrekadirbektas.keylock;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Represents a party in a Diffie-Hellman key exchange.
 * This class manages the private key and the computation of public and shared keys.
 */
public class KeyExchangeParty {
    private final String name;
    private final BigInteger privateKey;
    private final BigInteger publicKey;
    private BigInteger sharedSecretKey;

    /**
     * Constructor for a party in the Diffie-Hellman exchange.
     * Generates a private key and computes the corresponding public key.
     *
     * @param name The name of the party (e.g., "Alice").
     * @param p    The public prime modulus.
     * @param g    The public generator.
     */
    public KeyExchangeParty(String name, BigInteger p, BigInteger g) {
        this.name = name;
        // Private key is a random number 's' such that 1 < s < p-1
        this.privateKey = generatePrivateKey(p);
        // Public key is g^privateKey mod p
        this.publicKey = g.modPow(this.privateKey, p);
    }

    /**
     * Generates a secure random private key.
     *
     * @param p The prime modulus.
     * @return A random BigInteger in the valid range for a private key.
     */
    private BigInteger generatePrivateKey(BigInteger p) {
        SecureRandom random = new SecureRandom();
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        BigInteger key;
        do {
            // The private key should be in the range [1, p-2]
            key = new BigInteger(p.bitLength(), random);
        } while (key.compareTo(BigInteger.ONE) < 0 || key.compareTo(pMinusOne) >= 0);
        return key;
    }

    /**
     * Computes the shared secret key using the other party's public key.
     *
     * @param otherPartyPublicKey The public key received from the other party.
     * @param p                   The public prime modulus.
     */
    public void computeSharedSecretKey(BigInteger otherPartyPublicKey, BigInteger p) {
        // Shared secret is otherPartyPublicKey^privateKey mod p
        this.sharedSecretKey = otherPartyPublicKey.modPow(this.privateKey, p);
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public BigInteger getSharedSecretKey() {
        return sharedSecretKey;
    }

    public String getName() {
        return name;
    }
}