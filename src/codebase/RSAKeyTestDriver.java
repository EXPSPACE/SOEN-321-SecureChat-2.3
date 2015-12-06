package codebase;

import java.util.Arrays;

public class RSAKeyTestDriver {

	public static void main(String[] args) {
		Crypto aliceCrypto = new Crypto();
		Crypto bobCrypto = new Crypto();
		Crypto serverCrypto = new Crypto();
		
		System.out.println("===PUBLIC===");
		
		System.out.println("Alice: ");
		aliceCrypto.loadRSAPublicKey("certificate/alice.crt");
		System.out.println(aliceCrypto.getRsaPublicKey());
		
		System.out.println("Bob: ");
		bobCrypto.loadRSAPublicKey("certificate/bob.crt");
		System.out.println(bobCrypto.getRsaPublicKey());

		System.out.println("Server: ");
		serverCrypto.loadRSAPublicKey("certificate/server.crt");
		System.out.println(serverCrypto.getRsaPublicKey());
		
		System.out.println("===PRIVATE===");
		
		System.out.println("Alice: ");
		aliceCrypto.loadRSAPrivateKey("privatekey/alice.key.pem");
		System.out.println(aliceCrypto.getRsaPrivateKey());
		
		System.out.println("Bob: ");
		bobCrypto.loadRSAPrivateKey("privatekey/bob.key.pem");
		System.out.println(bobCrypto.getRsaPrivateKey());

		System.out.println("Server: ");
		serverCrypto.loadRSAPrivateKey("privatekey/server.key.pem");
		System.out.println(serverCrypto.getRsaPrivateKey());
		
		
		

	}

}
