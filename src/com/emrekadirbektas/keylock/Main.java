
package com.emrekadirbektas.keylock;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Main {
    // Use constants for parameters for better readability and maintenance
    private static final int DH_BIT_LENGTH = 512;
    private static final BigInteger GENERATOR = new BigInteger("5");

    public static void main(String[] args) {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(DH_BIT_LENGTH, random);

        System.out.println("--- KeyLock ---");
        System.out.println("Publicly agreed parameters:");
        System.out.printf("Prime (p): %s%n", p);
        System.out.printf("Generator (g): %s%n", GENERATOR);
        System.out.println("----------------------------------------------\n");

        // party1 and party2.
        // Each party generates their own private key and computes their public key.
        KeyExchangeParty party1 = new KeyExchangeParty("Party1", p, GENERATOR);
        KeyExchangeParty party2 = new KeyExchangeParty("Party2", p, GENERATOR);

        System.out.println("party1's private key is secret.");
        // System.out.println("party1's private key: " + party1.getPrivateKey());
        System.out.printf("party1's public key (sent to party2): %s%n%n", party1.getPublicKey());


        System.out.println("party2's private key is secret.");
        // For demonstration, you could print the private key:
        // System.out.println("party2's private key: " + party2.getPrivateKey());
        System.out.printf("party2's public key (sent to party1): %s%n", party2.getPublicKey());
        System.out.println("----------------------------------------------\n");

        // 3. Key Exchange
        // party1 computes the shared secret using party2's public key.
        party1.computeSharedSecretKey(party2.getPublicKey());

        // party2 computes the shared secret using party1's public key.
        party2.computeSharedSecretKey(party1.getPublicKey());

        System.out.println("--- Shared Secret Computation ---");
        System.out.printf("%s computes shared secret: %s%n", party1.getName(), party1.getSharedSecretKey());
        System.out.printf("%s computes shared secret:   %s%n", party2.getName(), party2.getSharedSecretKey());
        System.out.println("---------------------------------\n");

        // 4. Verification
        // Both parties should now have the same shared secret key.
        if (party1.getSharedSecretKey().equals(party2.getSharedSecretKey())) {
            System.out.println("SUCCESS: Shared secret keys match!");
            System.out.printf("The established shared secret is: %s%n", party1.getSharedSecretKey());
        } else {
            System.out.println("ERROR: Shared secret keys do NOT match!");
        }
    }
}