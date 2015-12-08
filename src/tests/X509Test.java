package tests;

import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import codebase.ChatCrypto;

public class X509Test {

	public static void main(String[] args) {
		ChatCrypto certTest = new ChatCrypto();
		certTest.loadCertificateName(new File("certificate/alice.crt"));
		System.out.println(certTest.getCertificateName());
	
	}

}
