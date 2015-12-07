package tests;

import java.io.File;
import java.util.Arrays;

import codebase.ChatCrypto;

public class RSAKeyTestDriver {

	public static void main(String[] args) {
		ChatCrypto aliceCrypto = new ChatCrypto();
		ChatCrypto bobCrypto = new ChatCrypto();
		ChatCrypto serverCrypto = new ChatCrypto();
		
		System.out.println("===PUBLIC===");
		
		System.out.println("Alice: ");
		aliceCrypto.loadRSAPublicKey(new File("certificate/alice.crt"));
		System.out.println(aliceCrypto.getRsaPublicKey());
		
		System.out.println("Bob: ");
		bobCrypto.loadRSAPublicKey(new File("certificate/bob.crt"));
		System.out.println(bobCrypto.getRsaPublicKey());

		System.out.println("Server: ");
		serverCrypto.loadRSAPublicKey(new File("certificate/server.crt"));
		System.out.println(serverCrypto.getRsaPublicKey());
		
		System.out.println("===PRIVATE===");
		
		System.out.println("Alice: ");
		aliceCrypto.loadRSAPrivateKey(new File("privatekey/alice.key.pem"));
		System.out.println(aliceCrypto.getRsaPrivateKey());
		
		System.out.println("Bob: ");
		bobCrypto.loadRSAPrivateKey(new File("privatekey/bob.key.pem"));
		System.out.println(bobCrypto.getRsaPrivateKey());

		System.out.println("Server: ");
		serverCrypto.loadRSAPrivateKey(new File("privatekey/server.key.pem"));
		System.out.println(serverCrypto.getRsaPrivateKey());
		
		
		

	}

}
