
package com.emrekadirbektas.keylock;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Main {
    // Use constants for parameters for better readability and maintenance
    private static final int DH_BIT_LENGTH = 512;
    private static final BigInteger GENERATOR = new BigInteger("5");

    // System-wide public parameters, generated once.
    private static final BigInteger p;

    // A map to act as our "user database" for the service
    private static final Map<String, KeyExchangeParty> parties = new HashMap<>();
    private static final Scanner scanner = new Scanner(System.in);

    static {
        // Generate the public prime 'p' when the application starts.
        SecureRandom random = new SecureRandom();
        p = BigInteger.probablePrime(DH_BIT_LENGTH, random);
    }

    public static void main(String[] args) {
        System.out.println("--- Diffie-Hellman Key Exchange Service Simulator ---");
        System.out.println("System-wide public parameters have been established.");
        System.out.printf("Prime (p): %s%n", p);
        System.out.printf("Generator (g): %s%n", GENERATOR);
        System.out.println("-----------------------------------------------------\n");

        while (true) {
            printMenu();
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            switch (choice) {
                case 1:
                    createNewParty();
                    break;
                case 2:
                    listParties();
                    break;
                case 3:
                    initiateExchange();
                    break;
                case 4:
                    System.out.println("Exiting service. Goodbye!");
                    return;
                default:
                    System.out.println("Invalid choice. Please try again.");
            }
            System.out.println(); // Add a blank line for readability
        }
    }

    private static void printMenu() {
        System.out.println("Select an action:");
        System.out.println("1. Create a new party (user)");
        System.out.println("2. List existing parties");
        System.out.println("3. Initiate key exchange between two parties");
        System.out.println("4. Exit");
        System.out.print("> ");
    }

    private static void createNewParty() {
        System.out.print("Enter the name for the new party: ");
        String name = scanner.nextLine();
        if (parties.containsKey(name)) {
            System.out.println("Error: A party with this name already exists.");
            return;
        }
        KeyExchangeParty newParty = new KeyExchangeParty(name, p, GENERATOR);
        parties.put(name, newParty);
        System.out.printf("Party '%s' created successfully.\n", name);
    }

    private static void listParties() {
        if (parties.isEmpty()) {
            System.out.println("No parties have been created yet.");
            return;
        }
        System.out.println("Existing parties:");
        for (String name : parties.keySet()) {
            System.out.println("- " + name);
        }
    }

    private static void initiateExchange() {
        if (parties.size() < 2) {
            System.out.println("Error: You need at least two parties to initiate an exchange.");
            return;
        }

        System.out.print("Enter the name of the first party: ");
        String name1 = scanner.nextLine();
        System.out.print("Enter the name of the second party: ");
        String name2 = scanner.nextLine();

        KeyExchangeParty party1 = parties.get(name1);
        KeyExchangeParty party2 = parties.get(name2);

        if (party1 == null || party2 == null) {
            System.out.println("Error: One or both parties not found.");
            return;
        }

        System.out.println("\n--- Initiating Key Exchange ---");
        System.out.printf("%s's public key (sent to %s): %s%n", party1.getName(), party2.getName(), party1.getPublicKey());
        System.out.printf("%s's public key (sent to %s): %s%n\n", party2.getName(), party1.getName(), party2.getPublicKey());

        // Perform the exchange
        party1.computeSharedSecretKey(party2.getPublicKey());
        party2.computeSharedSecretKey(party1.getPublicKey());

        System.out.println("--- Shared Secret Computation ---");
        System.out.printf("%s computes shared secret: %s%n", party1.getName(), party1.getSharedSecretKey());
        System.out.printf("%s computes shared secret:   %s%n", party2.getName(), party2.getSharedSecretKey());

        if (!party1.getSharedSecretKey().equals(party2.getSharedSecretKey())) {
            System.out.println("\nERROR: Shared secret keys do NOT match!");
            return;
        }

        System.out.println("\nSUCCESS: Shared secret keys match!");
        System.out.println("The two parties can now communicate securely.");
        System.out.println("-----------------------------------------------------\n");

        // --- New part: Encrypt and Decrypt a message ---
        System.out.printf("Enter a secret message to send from %s to %s:\n> ", party1.getName(), party2.getName());
        String message = scanner.nextLine();

        try {
            // party1 encrypts the message with the shared key
            String encryptedMessage = CryptoUtils.encrypt(message, party1.getSharedSecretKey());
            System.out.printf("\n[%s's side] Encrypted message (Ciphertext):\n%s\n", party1.getName(), encryptedMessage);

            // party2 decrypts the message with its shared key
            String decryptedMessage = CryptoUtils.decrypt(encryptedMessage, party2.getSharedSecretKey());
            System.out.printf("\n[%s's side] Decrypted message:\n%s\n", party2.getName(), decryptedMessage);

        } catch (Exception e) {
            System.err.println("An error occurred during encryption/decryption: " + e.getMessage());
            e.printStackTrace();
        }
    }
}