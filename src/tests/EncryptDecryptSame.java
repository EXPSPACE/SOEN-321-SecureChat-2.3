package tests;

import java.util.Arrays;

import codebase.ChatCrypto;

public class EncryptDecryptSame {
	public static void main(String[] args) {
		ChatCrypto clientCrypto = new ChatCrypto();
		ChatCrypto serverCrypto = new ChatCrypto();
		
		clientCrypto.genClientDHKeyPair();
		serverCrypto.genServerDHKeyPair(clientCrypto.getDHPublicKey());
		
	
		clientCrypto.genSharedSecretAESKey(serverCrypto.getDHPublicKey());
		serverCrypto.genSharedSecretAESKey(clientCrypto.getDHPublicKey());
		
		
		byte[] testMessage = "This is an ecryptable test message".getBytes();
		
		byte[] newMessage = clientCrypto.getEncryptedMsg(testMessage, new byte[16]);
		newMessage = clientCrypto.getDecryptedMsg(newMessage, new byte[16]);
		
		System.out.println(Arrays.equals(newMessage, testMessage));
		System.out.println(new String(testMessage));
	}

}
