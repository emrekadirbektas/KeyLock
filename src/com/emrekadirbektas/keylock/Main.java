
package com.emrekadirbektas.keylock;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Main {
    public static void main(String[] args) {
        
        int bitLength = 512; //test değeri
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength, random);
        BigInteger g = new BigInteger("5"); // test parametre

        System.out.println("--- KeyLock ---");
        System.out.println("Publicly agreed parameters:");
        System.out.printf("Prime (p): %s%n", p);
        System.out.printf("Generator (g): %s%n", g);
        System.out.println("----------------------------------------------\n");

        // 2. Create two parties, Party1 and Party2.
        // Each party generates their own private key and computes their public key.
        KeyExchangeParty Party1 = new KeyExchangeParty("Party1", p, g);
        KeyExchangeParty Party2 = new KeyExchangeParty("Party2", p, g);

        System.out.println("Party1's private key is secret.");
        // System.out.println("Party1's private key: " + Party1.getPrivateKey());
        System.out.printf("Party1's public key (sent to Party2): %s%n%n", Party1.getPublicKey());


        System.out.println("Party2's private key is secret.");
        // For demonstration, you could print the private key:
        // System.out.println("Party2's private key: " + Party2.getPrivateKey());
        System.out.printf("Party2's public key (sent to Party1): %s%n", Party2.getPublicKey());
        System.out.println("----------------------------------------------\n");

        // 3. Key Exchange
        // Party1 computes the shared secret using Party2's public key.
        Party1.computeSharedSecretKey(Party2.getPublicKey(), p);

        // Party2 computes the shared secret using Party1's public key.
        Party2.computeSharedSecretKey(Party1.getPublicKey(), p);

        System.out.println("--- Shared Secret Computation ---");
        System.out.printf("%s computes shared secret: %s%n", Party1.getName(), Party1.getSharedSecretKey());
        System.out.printf("%s computes shared secret:   %s%n", Party2.getName(), Party2.getSharedSecretKey());
        System.out.println("---------------------------------\n");

        // 4. Verification
        // Both parties should now have the same shared secret key.
        if (Party1.getSharedSecretKey().equals(Party2.getSharedSecretKey())) {
            System.out.println("SUCCESS: Shared secret keys match!");
            System.out.printf("The established shared secret is: %s%n", Party1.getSharedSecretKey());
        } else {
            System.out.println("ERROR: Shared secret keys do NOT match!");
        }
    }
}