package tests;

import java.io.File;

import codebase.*;

public class SigningDHPubKeyTest {

	public static void main(String[] args) {
				
		ChatCrypto clientCrypto = new ChatCrypto();
		ChatCrypto serverCrypto = new ChatCrypto();
		
		//load keys	
		clientCrypto.loadRSAPrivateKey(new File("privatekey/alice.key.pem"));
		clientCrypto.loadRSAPublicKey(new File("certificate/server.crt"));
			
		serverCrypto.loadRSAPrivateKey(new File("privatekey/server.key.pem"));
		serverCrypto.loadRSAPublicKey(new File("certificate/alice.crt"));
		
		//send client to server info
		clientCrypto.genClientDHKeyPair();
		ChatPacket cp = new ChatPacket();
		cp.dhPublicKey = clientCrypto.getDHPublicKey();
		cp.signature = clientCrypto.getSignature(cp.dhPublicKey.getEncoded());
		
		//---sending----
		
		//verify server side
		boolean verifiedServerSide = serverCrypto.verifySignature(cp.signature, cp.dhPublicKey.getEncoded());
		
		ChatPacket sp = null;
		
		if(verifiedServerSide) {
			System.out.println("verified pass server side");
			serverCrypto.genServerDHKeyPair(clientCrypto.getDHPublicKey());
			sp = new ChatPacket();
			sp.dhPublicKey = serverCrypto.getDHPublicKey();
			sp.signature = serverCrypto.getSignature(sp.dhPublicKey.getEncoded());
		} else {
			System.out.println("verified failed server side");
		}
		
		//---sending----
		
		//verify client side
		if(verifiedServerSide) {
			boolean verifiedClientSide = clientCrypto.verifySignature(sp.signature, sp.dhPublicKey.getEncoded());
			
			if(verifiedClientSide) {
				System.out.println("verified pass client side");
			} else {
				System.out.println("verified failed client side");
			}		
		}
		
		//establish key pairs
		
		serverCrypto.genSharedSecretAESKey(cp.dhPublicKey);
		clientCrypto.genSharedSecretAESKey(sp.dhPublicKey);
		
		byte[] testMessage = "This is an ecryptable test message".getBytes();
		
		testMessage = clientCrypto.getEncryptedMsg(testMessage, new byte[16]);
		testMessage = serverCrypto.getDecryptedMsg(testMessage, new byte[16]);
		
		System.out.println(new String(testMessage));

		
	}

}
