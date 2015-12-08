package codebase;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.X509Certificate;

import org.apache.commons.ssl.PKCS8Key;

public class ChatCrypto {
	
	public static final byte[] AUTH_CODE = new byte[16]; //AES forward secrecy resistant
	
	private String certificateName;
	private RSAPublicKey rsaPublicKey;   // public key of connection
	private RSAPrivateKey rsaPrivateKey; // self private key
	private KeyPair dhKeyPair;
	private SecretKey sharedSecretKey;    //message enc/dec key
	private boolean authenticated;
	
	/** DIFFIE-HELLMAN **/
	//methods for generating diffie-hellman public/private key pairs and performing key exchange
	
	public void genClientDHKeyPair() {
		try {
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DH");
			keyGenerator.initialize(1024);
			dhKeyPair = keyGenerator.genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	public void genServerDHKeyPair(PublicKey otherDHPublicKey) {
		DHParameterSpec dhSpec = new DHParameterSpec(
				((DHPublicKey)otherDHPublicKey).getParams().getP(), 
				((DHPublicKey)otherDHPublicKey).getParams().getG(), 
				((DHPublicKey)otherDHPublicKey).getParams().getL());	
		try {
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DH");
			keyGenerator.initialize(dhSpec);
			dhKeyPair = keyGenerator.genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}
	 
	public void genSharedSecretAESKey(PublicKey otherDHPublicKey) {
		try {
			//initialize with your own private key
			KeyAgreement ka = KeyAgreement.getInstance("DH");
			ka.init(dhKeyPair.getPrivate()); 		
			
			//initialize with other persons public key
			KeyFactory kf = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(otherDHPublicKey.getEncoded()); 
			PublicKey pk = kf.generatePublic(x509Spec);
			ka.doPhase(pk, true);
			
			//generate valid shared AES key
			byte[] secret = ka.generateSecret();
			sharedSecretKey = new SecretKeySpec(secret, 0, 16, "AES");
		
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}		
	}
	
	public PublicKey getDHPublicKey() {
		return dhKeyPair.getPublic();
	}
	
	/** SIGNATURES **/
	//methods using SHA-256 with RSA to sign/verify the diffie-hellman public key
	
	public byte[] getSignature(byte[] data) {
		try {
			Signature sig = Signature.getInstance("SHA256withRSA"); //set algorithm
			sig.initSign(rsaPrivateKey);  //set private key to sign
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
			sig.initVerify(rsaPublicKey);  //set public key to verify
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

	public void loadRSAPublicKey(File file) {
		try {
			FileInputStream fInputStream = new FileInputStream(file);
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			Certificate cert = certFactory.generateCertificate(fInputStream);
			rsaPublicKey = (RSAPublicKey) cert.getPublicKey();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}
	}
	
	//TODO set to unlock priv key with pass phrase from password text field
	public void loadRSAPrivateKey(File file) {	
		try {
            FileInputStream fileInputStream = new FileInputStream(file);
            PKCS8Key pkcs8Key = new PKCS8Key(fileInputStream,"1q2w".toCharArray());
            byte[] decrypted = pkcs8Key.getDecryptedBytes();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( decrypted );

            //create Java privateKey
            if(pkcs8Key.isRSA())
            {
            	rsaPrivateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
            }

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void loadCertificateName(File file) {
		try {		
			FileInputStream inStream = new FileInputStream(file);
			X509Certificate cert = X509Certificate.getInstance(inStream);
			
			Pattern p = Pattern.compile("(?<=CN=)[a-z]*");
			Matcher m = p.matcher(cert.getSubjectDN().getName());
			if (m.find()) {
				certificateName = m.group();
		    }
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (javax.security.cert.CertificateException e) {
			e.printStackTrace();
		}
	}
		
	/** AES CIPHER **/
	//symmetric key cryptography methods for encrypting/decrypting exchanged messages
	
	public byte[] getEncryptedMsg(byte[] message, byte[] iv) {
		Cipher cipher;
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
	
	
	public byte[] getDecryptedMsg(byte[] message, byte[] iv) {
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
	
	public void authenticateConnection(byte[] encAuthCode, byte[] iv) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, sharedSecretKey, new IvParameterSpec(iv));
			byte[] decAuthCode = cipher.doFinal(encAuthCode);
			authenticated = Arrays.equals(decAuthCode, AUTH_CODE);
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
	}
	
	public static byte[] genRandomIV() {
	      SecureRandom random = new SecureRandom();
	      byte[] iv = new byte[16];
	      random.nextBytes(iv);
	      return iv;
	}
	
	//forwards messages from one client to another on the server after both are authenticated
	public static void decryptReEncryptPacket(ChatPacket senderPacket, ChatCrypto senderInfo, ChatCrypto recieverInfo) {
		byte[] decryptedMsg = senderInfo.getDecryptedMsg(senderPacket.data, senderPacket.iv);
		byte[] iv = ChatCrypto.genRandomIV();
		byte[] encryptedMsg = recieverInfo.getEncryptedMsg(decryptedMsg, iv);
		senderPacket.data = encryptedMsg;
		senderPacket.iv = iv;
	}
	
	//TESTING
	public String getCertificateName() {
		return certificateName;
	}

	public RSAPublicKey getRsaPublicKey() {
		return rsaPublicKey;
	}

	public RSAPrivateKey getRsaPrivateKey() {
		return rsaPrivateKey;
	}

	public KeyPair getDhKeyPair() {
		return dhKeyPair;
	}

	public SecretKey getSharedSecretKey() {
		return sharedSecretKey;
	}

	public boolean isAuthenticated() {
		return authenticated;
	}


}
