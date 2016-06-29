package com.apigee.callout;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.io.IOUtils;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Condition;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.OneTimeUse;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;



public class SAMLAssertion {

	private static XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

	public SAMLAssertion() throws Exception{
		// OpenSAML 2.3
		DefaultBootstrap.bootstrap();
	}
	
	public static void main(String[] args) throws Exception {
		String privateKeyFile = "/resources/pkcs8.key";
		String password = "admin123";
		String certificateAliasName = "selfsigned";
		//String keyStore = "/resources/keystore.jks";
		String encAssertion = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<saml2:EncryptedAssertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">\n <xenc:EncryptedData Id=\"_cfe5117897dd13ce120140595059ffc1\"\n Type=\"http://www.w3.org/2001/04/xmlenc#Element\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\n <xenc:EncryptionMethod\n Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/>\n <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n <xenc:EncryptedKey Id=\"_131ba9b97befce88a033269b1596e0f2\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\n <xenc:EncryptionMethod\n Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\n <ds:DigestMethod\n Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>\n </xenc:EncryptionMethod>\n <ds:KeyInfo>\n <ds:X509Data>\n <ds:X509Certificate>MIIDjTCCAnWgAwIBAgIETL7AhDANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJDQTEQMA4GA1UE\nCBMHT250YXJpbzEQMA4GA1UEBxMHVG9yb250bzEPMA0GA1UEChMGQXBpZ2VlMRowGAYDVQQLExFT\nYWxlcyBFbmdpbmVlcmluZzEXMBUGA1UEAxMOd3d3LmFwaWdlZS5jb20wHhcNMTYwMTEzMTgzMjU5\nWhcNMTcwMTA3MTgzMjU5WjB3MQswCQYDVQQGEwJDQTEQMA4GA1UECBMHT250YXJpbzEQMA4GA1UE\nBxMHVG9yb250bzEPMA0GA1UEChMGQXBpZ2VlMRowGAYDVQQLExFTYWxlcyBFbmdpbmVlcmluZzEX\nMBUGA1UEAxMOd3d3LmFwaWdlZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCs\nwx3c8kJvHiqlVuIKYU7tNw9trdXdfHG4ctyvtpqhLPkrw95y1CVkzuw5Oleh4pATApGoNXYa7enk\n5+K6FdEyO6DzcWqpBdOR5eMpbQpg/dVJ4uGITq8CaiG0+ZeLn1NJdkc4ocw4wHmKfT7Tn3cg/c0S\nd5EX2BrqP1bMfP9Ceyik5KoN0kpnXz07S9DgK13KUMd7twEFuC+52bSOoox7OKnqtAX1nBHc5p7y\n+LYkLeAeqnkIxyfeWln/q3PULasFNASl93JjHcbr3B1gKAszG9dqmZ06Bwp51oAe+VMKm5BnzvdV\niJKtbCaJOgggkTjbK1PUJiy18tBpiL4VUEOpAgMBAAGjITAfMB0GA1UdDgQWBBQWaQIS4wKtvqKe\ngdbHUT2796dDkDANBgkqhkiG9w0BAQsFAAOCAQEAjArlWVE+A5l5PQXhC3/VK+7RrenUy3iFTNMB\n8VcM/M1mJqbk6RjtEHqTHnUROdcMZq1yYCPEjEJ/rxQ+bYcyQHfxLLjtDshdGUaKAH8h3vL2R2t/\nCcXlrPONR4HE7Nb6d+dmHGjhfkvRINYRgtGGKU/UKkJg+fsSHctcFtwRsbv3+RbjmMw/Xu6Vk0wC\nsbr0hc7h92f5Zbyu3bZrwwZcbJsAajLpdu9foCUW1dinBDyi9cpTgCSggpvnIsesv8xz73Rf3xHR\neWQTDMVAwqe26d+YPiS4qvdYotqfmj8StwTqGsWHmWuT9Xn/b73j5IaOinoeCaamlGAh4X9EmnFW\nZg==</ds:X509Certificate>\n </ds:X509Data>\n </ds:KeyInfo>\n <xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\n <xenc:CipherValue>JLZOJM/TBzJ/jRWPUl/2p+V44fT2lRSqj/UUIQ5O7ZXPXkJVaMoDBYEAAvFUaRk8CeSYtlao+WML67gmfD7xMTGi6Lhsd0ltfUbAlBkyGPhkQPP8HpJi7CsFSsJqHtPsAqwsBQk6L1TLrSu1hPfMY8PuAxUGy9VPylrxLHrBnSQ4aTw8LEieZWvHhZLuiU9KbX41yjD0Y09dbOku3HOQMG5AapS9EE/4Ots7FMPy5qw4bn3YgrpGIZej+ikbTgwR41yB7XRxDXeIw/WybATSrf9HhIxvp7829Z5hXyRYxQHUhQn4miDpuhYzUzPrJRY08PEBYKAV7cpMOX3LVqHrbA==</xenc:CipherValue>\n </xenc:CipherData>\n </xenc:EncryptedKey>\n </ds:KeyInfo>\n <xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\n <xenc:CipherValue>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</xenc:CipherValue>\n </xenc:CipherData>\n </xenc:EncryptedData>\n</saml2:EncryptedAssertion>";
		String publicKeyFileName = "/resources/public.pem";
		
		SAMLAssertion saml = new SAMLAssertion();
		//String encAssertion = saml.encrypt(password, certificateAliasName, privateKeyFile, publicKeyFileName, saml.getInput());
		Element decrpytedAssertion = saml.decrypt(encAssertion, privateKeyFile, publicKeyFileName);
		saml.printAssertion(decrpytedAssertion);

	}
	
	public String encrypt(String password, String certificateAliasName, String privateKeyFileName, String publicKeyFileName, SAMLInputContainer input) throws Exception {
		Assertion assertion = buildDefaultAssertion(input);
		Credential signingCredential = getCredentials(privateKeyFileName);
		assertion = signAssertion(assertion, signingCredential);
		Credential encryptionCredential = getCredentialFromFilePath(publicKeyFileName);
		EncryptedAssertion encryptedAssertion = encryptAssertion(assertion, encryptionCredential);
		return printEncryptedAssertion(encryptedAssertion);		
	}
	
	private SAMLInputContainer getInput() {
		SAMLInputContainer input = new SAMLInputContainer();
		input.setStrIssuer("http://synesty.com");
		input.setStrNameID("nhN1S9OFTw8ahZtU1TA5Vv8ESKEAISjl");//"UserJohnSmith";
		input.setStrNameQualifier("My Website");
		input.setSessionId("abcdedf1234567");

		Map<String,String> customAttributes = new HashMap<String, String>();
		customAttributes.put("FirstName", "John");
		customAttributes.put("LastName", "Smith");
		customAttributes.put("Email", "john.smith@yahoo.com");
		customAttributes.put("PhoneNumber", "76373898998");
		customAttributes.put("Locality", "USA");
		customAttributes.put("Username", "John.Smith");

		input.setAttributes(customAttributes);
		return input;
	}	
	
	public Element decrypt(String data, String privateKeyFile, String publicKeyFile) throws Exception{
		Element element = getAssertionData(data);
		EncryptedAssertion encryptedAssertion = getEncryptedAssertion(element);
		BasicX509Credential decryptionCredential = getCredentials(privateKeyFile);
		Assertion assertion = getDecryptedAssertion(encryptedAssertion, decryptionCredential);
		Signature signature = assertion.getSignature();
		if (signature != null) {
			if (!verifySignature(signature, getPublicKey(publicKeyFile))) {
				throw new SAMLValidationException("signature validation failed");
			}
		}
		return getPlainElement(assertion);
	}
	
	private Assertion getDecryptedAssertion(EncryptedAssertion encryptedAssertion,
			BasicX509Credential decryptionCredential) throws Exception {
		// Create a decrypter.
		Decrypter decrypter = new Decrypter(null, new StaticKeyInfoCredentialResolver(decryptionCredential),
				new InlineEncryptedKeyResolver());
		return decrypter.decrypt(encryptedAssertion);
	}

	public String printAssertion(Element plaintextElement) throws Exception {
		System.out.println(XMLHelper.prettyPrintXML(plaintextElement));
		return XMLHelper.prettyPrintXML(plaintextElement);
	}
	
	private Element getPlainElement (Assertion assertion) throws Exception {
		System.out.println("Assertion:");
		AssertionMarshaller marshaller = new AssertionMarshaller();
		Element plaintextElement = marshaller.marshall(assertion);
		return plaintextElement;
	}
	
	private String printEncryptedAssertion (EncryptedAssertion encryptedAssertion) throws Exception{
		System.out.println("Encrypted Assertion:");
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(encryptedAssertion);
        Element element = marshaller.marshall(encryptedAssertion);
        System.out.println(XMLHelper.prettyPrintXML(element));
		return XMLHelper.prettyPrintXML(element);
	}
	
	private EncryptedAssertion getEncryptedAssertion(Element element) throws Exception {
		// Unmarshall
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		EncryptedAssertion encryptedAssertion = (EncryptedAssertion) unmarshaller.unmarshall(element);
		return encryptedAssertion;
	}

	private BasicX509Credential getCredentials(String privateKeyFileName) throws Exception {
		// Load the private key file.
		InputStream inputStreamPrivateKey = getClass().getResourceAsStream(privateKeyFileName);
		byte[] encodedPrivateKey = IOUtils.toByteArray(inputStreamPrivateKey);

		// PKCS8 decode the encoded RSA private key
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = (PrivateKey) kf.generatePrivate(spec);

		// Create the credentials.
		BasicX509Credential decryptionCredential = new BasicX509Credential();
		decryptionCredential.setPrivateKey(privateKey);

		return decryptionCredential;
	}

	private Element getAssertionData(String data) throws Exception {
		// Load the XML file and parse it.
		DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
		docBuilderFactory.setNamespaceAware(true);
		DocumentBuilder builder = docBuilderFactory.newDocumentBuilder();
		InputStream inputStream = null;
		Document document = null;
		File xmlFile = new File(data);
		
		try {
			inputStream = new FileInputStream(xmlFile);
			document = builder.parse(inputStream);
		} catch (Exception e) {
			document = builder.parse(new InputSource(new StringReader(data)));
		}
		Element metadataRoot = document.getDocumentElement();
		return metadataRoot;
	}
	
	private EncryptedAssertion encryptAssertion(Assertion assertion, Credential encryptionCredential) throws Exception{
		EncryptionParameters encParams = new EncryptionParameters();
		encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

		KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
		kekParams.setEncryptionCredential(encryptionCredential);
		kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
		KeyInfoGeneratorFactory kigf = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager()
				.getDefaultManager().getFactory(encryptionCredential);
		kekParams.setKeyInfoGenerator(kigf.newInstance());

		Encrypter samlEncrypter = new Encrypter(encParams, kekParams);
		samlEncrypter.setKeyPlacement(KeyPlacement.INLINE);

		EncryptedAssertion encryptedAssertion = samlEncrypter.encrypt(assertion);
		return encryptedAssertion;
	}

	private Credential initializeCredentials(String pwd, String keyStoreFileName, String certificateAliasName) {
		KeyStore ks = null;
		char[] password = pwd.toCharArray();

		// Get Default Instance of KeyStore
		try
		{
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
		}
		catch (KeyStoreException e) {
			e.printStackTrace();
		}

		// Load KeyStore
		try {
			ks.load(getClass().getResourceAsStream(keyStoreFileName), password);
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		catch (java.security.cert.CertificateException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		// Get Private Key Entry From Certificate
		KeyStore.PrivateKeyEntry pkEntry = null;
		try
		{
			pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(certificateAliasName, new KeyStore.PasswordProtection(
					password));
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		catch (UnrecoverableEntryException e) {
			e.printStackTrace();
		}
		catch (KeyStoreException e) {
			e.printStackTrace();
		}

		PrivateKey pk = pkEntry.getPrivateKey();

		X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityCertificate(certificate);
		credential.setPrivateKey(pk);
		return credential;
	}
	
	public boolean verifySignature(Signature signature, Credential credential) throws Exception{
        SignatureValidator signatureValidator = new SignatureValidator(credential);
        signatureValidator.validate(signature);		
        return true;
	}
	
	private Assertion signAssertion(Assertion assertion, Credential signingCredential) {
		Signature signature = null;            
		signature = (Signature) Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME)
				.buildObject(Signature.DEFAULT_ELEMENT_NAME);

		signature.setSigningCredential(signingCredential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);               
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		// This is also the default if a null SecurityConfiguration is specified
		SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
		NamedKeyInfoGeneratorManager namedKeyInfoGeneratorManager = secConfig.getKeyInfoGeneratorManager(); 
		KeyInfoGeneratorManager keyInfoGeneratorManager = namedKeyInfoGeneratorManager.getDefaultManager();
		KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(signingCredential);
		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
		KeyInfo keyInfo = null;


		try {
			keyInfo = keyInfoGenerator.generate(signingCredential);
		} catch  (SecurityException e) {
			e.printStackTrace();
		}
		signature.setKeyInfo(keyInfo);

		try {
			MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
			assertion.setSignature(signature);
			marshallerFactory.getMarshaller(assertion).marshall(assertion);
			Signer.signObject(signature);
			
		} catch (MarshallingException e){
			e.printStackTrace();
		} catch (SignatureException e){
			e.printStackTrace();
		}
		
		return assertion;
	}	
	
	/**
	 * Helper method which includes some basic SAML fields which are part of almost every SAML Assertion.
	 */
	@SuppressWarnings("rawtypes")
	public Assertion buildDefaultAssertion(SAMLInputContainer input){
		try {
			// Create the NameIdentifier
			SAMLObjectBuilder nameIdBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
			NameID nameId = (NameID) nameIdBuilder.buildObject();
			nameId.setValue(input.getStrNameID());
			nameId.setNameQualifier(input.getStrNameQualifier());
			nameId.setFormat(NameID.UNSPECIFIED);

			// Create the SubjectConfirmation

			SAMLObjectBuilder confirmationMethodBuilder = (SAMLObjectBuilder)  builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
			SubjectConfirmationData confirmationMethod = (SubjectConfirmationData) confirmationMethodBuilder.buildObject();
			DateTime now = new DateTime();
			confirmationMethod.setNotBefore(now);
			confirmationMethod.setNotOnOrAfter(now.plusMinutes(2));

			SAMLObjectBuilder subjectConfirmationBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
			SubjectConfirmation subjectConfirmation = (SubjectConfirmation) subjectConfirmationBuilder.buildObject();
			subjectConfirmation.setSubjectConfirmationData(confirmationMethod);

			// Create the Subject
			SAMLObjectBuilder subjectBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
			Subject subject = (Subject) subjectBuilder.buildObject();

			subject.setNameID(nameId);
			subject.getSubjectConfirmations().add(subjectConfirmation);

			// Create Authentication Statement
			SAMLObjectBuilder authStatementBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
			AuthnStatement authnStatement = (AuthnStatement) authStatementBuilder.buildObject();
			//authnStatement.setSubject(subject);
			//authnStatement.setAuthenticationMethod(strAuthMethod);
			DateTime now2 = new DateTime();
			authnStatement.setAuthnInstant(now2);
			authnStatement.setSessionIndex(input.getSessionId());
			authnStatement.setSessionNotOnOrAfter(now2.plus(input.getMaxSessionTimeoutInMinutes()));

			SAMLObjectBuilder authContextBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
			AuthnContext authnContext = (AuthnContext) authContextBuilder.buildObject();

			SAMLObjectBuilder authContextClassRefBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
			AuthnContextClassRef authnContextClassRef = (AuthnContextClassRef) authContextClassRefBuilder.buildObject();
			authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"); // TODO not sure exactly about this

			authnContext.setAuthnContextClassRef(authnContextClassRef);
			authnStatement.setAuthnContext(authnContext);

			// Builder Attributes
			SAMLObjectBuilder attrStatementBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
			AttributeStatement attrStatement = (AttributeStatement) attrStatementBuilder.buildObject();

			// Create the attribute statement
			Map attributes = input.getAttributes();
			if(attributes != null){
				Iterator keySet = attributes.keySet().iterator();
				while (keySet.hasNext()){
					String key = keySet.next().toString();
					String val = attributes.get(key).toString();
					Attribute attrFirstName = buildStringAttribute(key, val, builderFactory);
					attrStatement.getAttributes().add(attrFirstName);
				}
			}

			// Create the do-not-cache condition
			SAMLObjectBuilder doNotCacheConditionBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(OneTimeUse.DEFAULT_ELEMENT_NAME);
			Condition condition = (Condition) doNotCacheConditionBuilder.buildObject();

			SAMLObjectBuilder conditionsBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
			Conditions conditions = (Conditions) conditionsBuilder.buildObject();
			conditions.getConditions().add(condition);

			// Create Issuer
			SAMLObjectBuilder issuerBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Issuer issuer = (Issuer) issuerBuilder.buildObject();
			issuer.setValue(input.getStrIssuer());

			// Create the assertion
			SAMLObjectBuilder assertionBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
			Assertion assertion = (Assertion) assertionBuilder.buildObject();
			assertion.setIssuer(issuer);
			assertion.setIssueInstant(now);
			assertion.setVersion(SAMLVersion.VERSION_20);

			assertion.getAuthnStatements().add(authnStatement);
			assertion.getAttributeStatements().add(attrStatement);
			assertion.setConditions(conditions);
			
			//NANDAN
			assertion.setSubject(subject);

			return assertion;
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	@SuppressWarnings("rawtypes")
	public Attribute buildStringAttribute(String name, String value, XMLObjectBuilderFactory builderFactory) throws ConfigurationException{
		SAMLObjectBuilder attrBuilder = (SAMLObjectBuilder) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
		Attribute attrFirstName = (Attribute) attrBuilder.buildObject();
		attrFirstName.setName(name);

		// Set custom Attributes
		XMLObjectBuilder stringBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);
		XSString attrValueFirstName = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		attrValueFirstName.setValue(value);

		attrFirstName.getAttributeValues().add(attrValueFirstName);
		return attrFirstName;
	}

	private BasicX509Credential getPublicKey (String publicKeyFileName) throws Exception{
		//Get Public Key
		InputStream inStream = getClass().getResourceAsStream(publicKeyFileName);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		java.security.cert.Certificate cert = cf.generateCertificate(inStream);
		inStream.close();
		
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(cert.getPublicKey().getEncoded());
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		// Create the credentials.
		BasicX509Credential signingCredential = new BasicX509Credential();
		signingCredential.setPublicKey(publicKey);
		return signingCredential;
	}
	
	private Credential getCredentialFromFilePath(String certPath)
			throws IOException, KeyException, java.security.cert.CertificateException {

		InputStream inStream = getClass().getResourceAsStream(certPath);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		java.security.cert.Certificate cert = cf.generateCertificate(inStream);
		inStream.close();

		BasicX509Credential cred = new BasicX509Credential();
		cred.setEntityCertificate((java.security.cert.X509Certificate) cert);
		cred.setPrivateKey(null);

		return cred;
	}
	
	public Map<String, String> getAttributes(Element samlAssertion) {
		
		Map<String, String> samlAttributes = new HashMap<String, String>();
		Node attributeStatement = samlAssertion.getElementsByTagName("saml2:AttributeStatement").item(0);
		NodeList attributeList = attributeStatement.getChildNodes();
		
		for(int i=0; i<attributeList.getLength(); i++) {
			Node attribute = attributeList.item(i);
			NamedNodeMap namedNodeMap = attribute.getAttributes();
			
			NodeList attributeValuesList = attribute.getChildNodes();
			for(int j=0; j<attributeValuesList.getLength(); j++) {
				Node attributeValue = attributeValuesList.item(j);
				samlAttributes.put(namedNodeMap.getNamedItem("Name").getNodeValue(),attributeValue.getTextContent());
				System.out.println(namedNodeMap.getNamedItem("Name").getNodeValue()+ " - " + attributeValue.getTextContent());
			}
		}
		
		return samlAttributes;
	}
	
	public String getSubjectName(Element plaintext) {
		Node subject = plaintext.getElementsByTagName("saml2:NameID").item(0);
		return subject.getTextContent();
	}
	
	public String getIssuer(Element plaintext) {
		Node issuer = plaintext.getElementsByTagName("saml2:Issuer").item(0);
		return issuer.getTextContent();
	}
}
