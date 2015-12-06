package tests;

import java.security.PublicKey;
import java.util.Arrays;

import codebase.Crypto;

public class DHTestDriver {

	public static void main(String[] args) {
		Crypto clientCrypto = new Crypto();
		Crypto serverCrypto = new Crypto();
		
		clientCrypto.genClientDHKeyPair();
		serverCrypto.genServerDHKeyPair(clientCrypto.getDHPublicKey());
		
		String form = clientCrypto.getDHPublicKey().getFormat();
		
		System.out.println("Public Key A: ");
		System.out.println(form);
		System.out.println(clientCrypto.getDHPublicKey());
		
		
		form = serverCrypto.getDHPublicKey().getFormat();
		
		System.out.println("Public Key S: ");
		System.out.println(form);
		System.out.println(serverCrypto.getDHPublicKey());
		
		clientCrypto.genSharedSecretAESKey(serverCrypto.getDHPublicKey());
		serverCrypto.genSharedSecretAESKey(clientCrypto.getDHPublicKey());
		
		System.out.println("Secret Key A: ");
		System.out.println(clientCrypto.getSharedSecretKey().getFormat());
		System.out.println(Arrays.toString(clientCrypto.getSharedSecretKey().getEncoded()));
		
		System.out.println("Secret Key S: ");
		System.out.println(clientCrypto.getSharedSecretKey().getFormat());
		System.out.println(Arrays.toString(serverCrypto.getSharedSecretKey().getEncoded()));
		
		byte[] testMessage = "This is an ecryptable test message".getBytes();
		
		testMessage = clientCrypto.getEncryptedMsg(testMessage);
		testMessage = serverCrypto.getDecryptedMsg(testMessage, new byte[16]);
		
		System.out.println(new String(testMessage));
	}

}
