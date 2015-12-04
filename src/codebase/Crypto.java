package codebase;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class Crypto {
	/*
	 * SHA-256 RSA Signature 
	 * use these to sign/verify dh parameters
	 * 
	 */
	public static byte[] getSignature(PrivateKey privateKey, byte[] data) {
		try {
			Signature sig = Signature.getInstance("SHA256withRSA"); //set algorithm
			sig.initSign(privateKey);  //set private key to sign
			sig.update(data); //set data to sign
			return sig.sign(); //return signature	
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static boolean verifySignature(PublicKey publicKey, byte[] signature, byte[] data) {
		try {
			Signature sig = Signature.getInstance("SHA256withRSA"); //set algorithm
			sig.initVerify(publicKey);  //set public key to verify
			sig.update(data); //set data to verify
			return sig.verify(signature); //verifies signature	
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return false;
	}

}
