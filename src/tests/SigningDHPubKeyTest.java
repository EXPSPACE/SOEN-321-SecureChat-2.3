package tests;

import codebase.*;

public class SigningDHPubKeyTest {

	public static void main(String[] args) {
				
		Crypto clientCrypto = new Crypto();
		Crypto serverCrypto = new Crypto();
		
		//load keys	
		clientCrypto.loadRSAPrivateKey("privatekey/alice.key.pem");
		clientCrypto.loadRSAPublicKey("certificate/server.crt");
			
		serverCrypto.loadRSAPrivateKey("privatekey/server.key.pem");
		serverCrypto.loadRSAPublicKey("certificate/alice.crt");
		
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

		
	}

}
