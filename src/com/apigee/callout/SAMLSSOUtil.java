package com.apigee.callout;

import java.util.Random;

import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.xml.ConfigurationException;

public class SAMLSSOUtil {
	
	private static boolean isBootStrapped = false;
	private static Random random = new Random();
	private static final char[] charMapping = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p' };
	
	public static String createID() {

		byte[] bytes = new byte[20]; // 160 bits
		random.nextBytes(bytes);

		char[] chars = new char[40];

		for (int i = 0; i < bytes.length; i++) {
			int left = (bytes[i] >> 4) & 0x0f;
			int right = bytes[i] & 0x0f;
			chars[i * 2] = charMapping[left];
			chars[i * 2 + 1] = charMapping[right];
		}

		return String.valueOf(chars);
	}
	
	/**
	 * Get the Issuer
	 * 
	 * @return Issuer
	 */
	public static Issuer getIssuer() {
		Issuer issuer = new IssuerBuilder().buildObject();
		issuer.setValue("http://www.apigee.com/about");
		issuer.setFormat(NameIDType.ENTITY);
		return issuer;
	}

	public static void doBootstrap() {
		if (!isBootStrapped) {
			try {
				DefaultBootstrap.bootstrap();
				isBootStrapped = true;
			} catch (ConfigurationException e) {
				System.out.println("Error in bootstrapping the OpenSAML2 library");
			}
		}
	}
}
