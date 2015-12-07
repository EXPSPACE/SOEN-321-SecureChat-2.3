package tests;

import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import codebase.ChatCrypto;

public class X509Test {

	public static void main(String[] args) {
		ChatCrypto AliceTest = new ChatCrypto();
		AliceTest.loadCertificateName(new File("certificate/bob.crt"));
		System.out.println(AliceTest.getCertificateName());
	
	}

}
