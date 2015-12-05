package codebase;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Crypto {
	
	private String connection;
	private RSAPublicKey certPublicKey;   // public key of connection
	private RSAPrivateKey certPrivateKey; // self private key
	//private DHKeyPair dhKeyPair
	private SecretKey sharedSecretKey;    //message enc/dec key
	
	/** DIFFIE-HELLMAN **/
	//asymmetric key cryptography methods for generating diffie-hellman public/private key pairs
	
//	public static KeyPair generateDHKeyPair() {
//		
//	}
//	 
//	public static SecretKey generateSharedSecretKey(Dhpublic otherskey) {
//		sharedSecretKey = ...
//	}
//	
	
	
	
	/** SIGNATURES **/
	//methods using SHA-256 with RSA to sign/verify the diffie-hellman public key
	
	public byte[] getSignature(byte[] data) {
		try {
			Signature sig = Signature.getInstance("SHA256withRSA"); //set algorithm
			sig.initSign(certPrivateKey);  //set private key to sign
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
	
	public boolean verifySignature(byte[] signature, byte[] data) {
		try {
			Signature sig = Signature.getInstance("SHA256withRSA"); //set algorithm
			sig.initVerify(certPublicKey);  //set public key to verify
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
	
	/** CERTIFICATES **/
	//methods for accessing certificate private/public keys 

	public void loadCertificatePublicKey(String filepath) {
		try {
			FileInputStream fis = new FileInputStream(filepath);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Certificate cert = cf.generateCertificate(fis);
			certPublicKey = (RSAPublicKey) cert.getPublicKey();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}
	}
	
	
	public void loadCertificatePrivateKey(String filepath) {
		
		//TODO get encoded private key from filepath (is key encrypted?)
		byte[] encodedKey = null;
		
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			KeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
			certPrivateKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/** AES CIPHER **/
	//symmetric key cryptography methods for encrypting/decrypting exchanged messages
	
	public byte[] getEncryptedMessage(byte[] message) {
		Cipher cipher;
		byte[] iv = new byte[16]; //TODO : Generate unique iv each time message is encrypted (prevents replay attacks?)
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, sharedSecretKey, new IvParameterSpec(iv));
			return cipher.doFinal(message);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	
	public byte[] getDecryptedMessage(byte[] message, byte[] iv) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, sharedSecretKey, new IvParameterSpec(iv));
			return cipher.doFinal(message);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}	
}
