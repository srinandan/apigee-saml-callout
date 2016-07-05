package com.apigee.callout;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

public class SAML2Assertion {

    /**
     * Maximum time from response creation when the message is deemed valid 
     */ 
    private int DEFAULT_RESPONSE_SKEW = 60;
    
	public static final String SUCCESS_CODE = "urn:oasis:names:tc:SAML:2.0:status:Success";
	
	public static final String SUBJECT_CONFIRM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
	
	private static Random random = new Random();
	
	private static final char[] charMapping = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
			'o', 'p' };

	private static XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

	private String audienceURI;
	private String recepient;
	private String destination;
	private String issuerString;

	private int expiry;
	
	private boolean audienceRequired;

	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			e.printStackTrace();
		}
	}

	public SAML2Assertion() {
		// default expiry
		expiry = 60 * 60 * 1000;
		audienceRequired = false;
	}

	public static void main(String[] args) throws Exception {
		String privateKeyFile = "/resources/pkcs8.key";
		String publicKeyFile = "/resources/public.pem";
		//String publicKeyFile = "/resources/sei_public.pem";

		SAML2Assertion saml = new SAML2Assertion();

		System.out.println(saml.getBase64PrivateKey(privateKeyFile));
		BasicX509Credential publicKey = saml.getPublicKey(publicKeyFile);
		BasicX509Credential privateKey = saml.getCredentials(privateKeyFile);
		Certificate certificate = saml.getCertificate(publicKeyFile);

		saml.setAudienceURI("http://www.apigee.com/");
		saml.setDestination("http://www.apigee.com/");
		saml.setRecepient("http://www.apigee.com/");
		saml.setIssuerString("https://test.apigee.com");

		
		 Response response = saml.buildSAMLResponse(true, true, "ssridhar@apigee.com", saml.getAttributes(), publicKey, privateKey,certificate); 
		 saml.printResponse(response);
		  
		 //Assertion assertion = saml.decrypt(response.getEncryptedAssertions().get(0), privateKeyFile);
		 

		//Assertion assertion = saml.decrypt(sampleSAML2, privateKeyFile);
		//if (!saml.verifyAssertion(assertion, publicKeyFile)) {
		//	throw new ValidationException("signature not valid!");
		//}
		//Element plaintext = saml.getPlainElement(assertion);
		//saml.printAssertion(plaintext);

		//System.out.println(saml.getSAMLProperties(assertion));

	}
	
	public void setAudienceRequuired(boolean ar) {
		audienceRequired = ar;
	}

	public void setExiry(int e) {
		expiry = e;
	}

	public void setIssuerString(String i) {
		issuerString = i;
	}

	public void setDestination(String d) {
		destination = d;
	}

	public void setRecepient(String r) {
		recepient = r;
	}

	public void setAudienceURI(String uri) {
		audienceURI = uri;
	}
	
	private String getBase64PrivateKey(String privateKeyFileName) throws Exception {
		// Load the private key file.
		InputStream inputStreamPrivateKey = getClass().getResourceAsStream(privateKeyFileName);
		byte[] encodedPrivateKey = IOUtils.toByteArray(inputStreamPrivateKey);
		byte[] base64EncodedPrivateKey = Base64.encodeBase64(encodedPrivateKey);
		return new String(base64EncodedPrivateKey);
	}

	private BasicX509Credential getPublicKey(byte[] publiccert) throws Exception {
		InputStream inStream = new ByteArrayInputStream(publiccert);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		java.security.cert.Certificate cert = cf.generateCertificate(inStream);
		inStream.close();
		return getX509Credential(cert);
	}

	private BasicX509Credential getX509Credential(java.security.cert.Certificate cert) throws Exception {
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(cert.getPublicKey().getEncoded());
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		// Create the credentials.
		BasicX509Credential signingCredential = new BasicX509Credential();
		signingCredential.setPublicKey(publicKey);
		return signingCredential;
	}
	
	private BasicX509Credential getCredentials(byte[] encodedPrivateKey) throws Exception {
		
		byte[] decodedPrivateKey = Base64.decodeBase64(encodedPrivateKey);
		
		// PKCS8 decode the encoded RSA private key
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedPrivateKey);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = (PrivateKey) kf.generatePrivate(spec);

		// Create the credentials.
		BasicX509Credential decryptionCredential = new BasicX509Credential();
		decryptionCredential.setPrivateKey(privateKey);

		return decryptionCredential;
	}

	private BasicX509Credential getPublicKey(String publicKeyFileName) throws Exception {
		// Get Public Key
		InputStream inStream = getClass().getResourceAsStream(publicKeyFileName);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		java.security.cert.Certificate cert = cf.generateCertificate(inStream);
		inStream.close();
		return getX509Credential(cert);
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

	public boolean verifyAssertion(Assertion assertion, byte[] publiccert) throws Exception {
		return verifyAssertion(assertion, getPublicKey(publiccert));
	}

	public boolean verifyAssertion(Assertion assertion, String publicKeyFile) throws Exception {
		return verifyAssertion(assertion, getPublicKey(publicKeyFile));
	}
	
	private boolean verifyResponse(Response response, Credential validatingCredential)
			throws Exception {
		if (response.isSigned()) {
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			profileValidator.validate(response.getSignature());

		    SignatureValidator signatureValidator = new SignatureValidator(validatingCredential); 
		    if (response.getSignature() != null) {
		    	signatureValidator.validate(response.getSignature()); 
			}
		}
		return true;
	}

	public boolean verifyAssertion(Assertion assertion, Credential validatingCredential)
			throws Exception {
		if (assertion.isSigned()) {
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			profileValidator.validate(assertion.getSignature());
			
			//TODO: this is not working doe sha-256 signed assertions
		    /*SignatureValidator signatureValidator = new SignatureValidator(validatingCredential); 
		    if (assertion.getSignature() != null) {
		    	signatureValidator.validate(assertion.getSignature()); 
			}*/
			 
		}
		
		if (assertion.getIssuer().getFormat() != null && !assertion.getIssuer().getFormat().equals(NameIDType.ENTITY)) {
			throw new ValidationException("SAML Assertion is invalid.  Assertion invalidated by issuer type");
		}
		
		if (assertion.getConditions().getNotBefore() != null && assertion.getConditions().getNotBefore().isAfterNow()) {
			throw new ValidationException("Condition states that assertion is not yet valid");
		}

		if (assertion.getConditions().getNotOnOrAfter() != null
				&& (assertion.getConditions().getNotOnOrAfter().isBeforeNow()
						|| assertion.getConditions().getNotOnOrAfter().isEqualNow())) {
			throw new ValidationException("Condition states that assertion is no longer valid");
		}
		return true;
	}
	
	public Assertion decrypt(String encryptedResponse, byte[] privateKey) throws Exception {
		return decrypt(encryptedResponse, getCredentials(privateKey));
	}

	public Assertion decrypt(String encryptedResponse, String privateKeyFile) throws Exception {
		return decrypt(encryptedResponse, getCredentials(privateKeyFile));
	}

	private Assertion decrypt(String encryptedResponse, BasicX509Credential privateKey) throws Exception {
		Element element = getResponseData(encryptedResponse);
		Response response = getResponse(element);

        // Verify issue time 
        DateTime time = response.getIssueInstant(); 
        if (!isDateTimeSkewValid(DEFAULT_RESPONSE_SKEW, time, "Response")) { 
            throw new SAMLException("Error validating SAML response.  Response issue time is either too old or a date in the future."); 
        } 		
		
		if (!response.getEncryptedAssertions().isEmpty()) {
			return decrypt(response.getEncryptedAssertions().get(0), privateKey);
		} else {
			return response.getAssertions().get(0);
		}
	}

	public Assertion decrypt(EncryptedAssertion encryptedAssertion, String privateKeyFile) throws Exception {
		return decrypt(encryptedAssertion, getCredentials(privateKeyFile));
	}

	private Assertion decrypt(EncryptedAssertion encryptedAssertion, BasicX509Credential privateKey) throws Exception {
		KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(privateKey);

		EncryptedKey key = encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0);
		Decrypter decrypter = new Decrypter(null, keyResolver, null);
		SecretKey dkey = (SecretKey) decrypter.decryptKey(key,
				encryptedAssertion.getEncryptedData().getEncryptionMethod().getAlgorithm());
		Credential shared = SecurityHelper.getSimpleCredential(dkey);
		decrypter = new Decrypter(new StaticKeyInfoCredentialResolver(shared), keyResolver, null);
		decrypter.setRootInNewDocument(true);
		return decrypter.decrypt(encryptedAssertion);
	}

	public Response buildSAMLResponse(boolean sign, boolean encrypt, String userName,
			Map<String, String> customAttributes, BasicX509Credential publicKey, BasicX509Credential privateKey,
			Certificate certificate) throws Exception {
		Response response = new org.opensaml.saml2.core.impl.ResponseBuilder().buildObject();
		response.setIssuer(getIssuer());
		response.setID(createID());
		response.setDestination(destination);
		response.setStatus(buildStatus(SUCCESS_CODE, null));
		response.setVersion(SAMLVersion.VERSION_20);
		DateTime issueInstant = new DateTime();
		DateTime notOnOrAfter = new DateTime(issueInstant.getMillis() + expiry);
		response.setIssueInstant(issueInstant);
		Assertion assertion = buildSAMLAssertion(sign, notOnOrAfter, userName, customAttributes, privateKey,
				certificate);
		if (encrypt) {
			EncryptedAssertion encryptedAssertion = encryptAssertion(assertion, publicKey);
			response.getEncryptedAssertions().add(encryptedAssertion);
			if (sign) {
				response = setSignature(response, privateKey, certificate);
			}
		}
		return response;
	}

	/**
	 * Get status
	 * 
	 * @param status
	 * @param statMsg
	 * @return Status object
	 */
	private Status buildStatus(String status, String statMsg) {

		Status stat = new StatusBuilder().buildObject();

		// Set the status code
		StatusCode statCode = new StatusCodeBuilder().buildObject();
		statCode.setValue(status);
		stat.setStatusCode(statCode);

		// Set the status Message
		if (statMsg != null) {
			StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
			statMesssage.setMessage(statMsg);
			stat.setStatusMessage(statMesssage);
		}

		return stat;
	}

	private EncryptedAssertion encryptAssertion(Assertion assertion, Credential encryptionCredential) throws Exception {
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

	/**
	 * Sign the SAML Response message
	 * 
	 * @param response
	 * @param signingCredential
	 * @param certificate
	 * @return
	 * @throws Exception
	 */
	public static Response setSignature(Response response, X509Credential signingCredential,
			java.security.cert.Certificate certificate) throws Exception {
		// SAMLSSOUtil.doBootstrap();
		try {
			Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
			signature.setSigningCredential(signingCredential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

			try {
				KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
				X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
				X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);
				cert.setValue(org.apache.xml.security.utils.Base64.encode(certificate.getEncoded()));
				data.getX509Certificates().add(cert);
				keyInfo.getX509Datas().add(data);
				signature.setKeyInfo(keyInfo);
			} catch (Exception e) {
				throw new Exception("errorGettingCert");
			}

			response.setSignature(signature);

			List<Signature> signatureList = new ArrayList<Signature>();
			signatureList.add(signature);

			// Marshall and Sign
			MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
			Marshaller marshaller = marshallerFactory.getMarshaller(response);

			marshaller.marshall(response);

			org.apache.xml.security.Init.init();
			Signer.signObjects(signatureList);
			return response;

		} catch (Exception e) {
			throw new Exception("Error while signing the SAML Response message.");
		}
	}

	/**
	 * Builds SAML Elements
	 * 
	 * @param objectQName
	 * @return
	 * @throws Exception
	 */
	private static XMLObject buildXMLObject(QName objectQName) throws Exception {
		@SuppressWarnings("unchecked")
		XMLObjectBuilder<XMLObject> builder = builderFactory.getBuilder(objectQName);
		if (builder == null) {
			throw new Exception("Unable to retrieve builder for object QName " + objectQName);
		}
		return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
	}

	/**
	 * Build SAML assertion
	 * 
	 * @param sign
	 * @param notOnOrAfter
	 * @param userName
	 * @param privateKey
	 * @param certificate
	 * @return Assertion
	 * @throws Exception
	 */
	private Assertion buildSAMLAssertion(boolean sign, DateTime notOnOrAfter, String userName,
			Map<String, String> customAttributes, BasicX509Credential privateKey, Certificate certificate)
			throws Exception {
		DateTime currentTime = new DateTime();
		Assertion samlAssertion = new AssertionBuilder().buildObject();
		samlAssertion.setID(createID());
		samlAssertion.setVersion(SAMLVersion.VERSION_20);
		samlAssertion.setIssuer(getIssuer());
		samlAssertion.setIssueInstant(currentTime);
		Subject subject = new SubjectBuilder().buildObject();
		NameID nameId = new NameIDBuilder().buildObject();

		nameId.setValue(userName);
		nameId.setFormat(NameIdentifier.EMAIL);
		subject.setNameID(nameId);

		SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
		subjectConfirmation.setMethod(SUBJECT_CONFIRM_BEARER);

		SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject();
		subjectConfirmationData.setRecipient(recepient);
		subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);

		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
		subject.getSubjectConfirmations().add(subjectConfirmation);
		samlAssertion.setSubject(subject);

		AuthnStatement authStmt = new AuthnStatementBuilder().buildObject();
		authStmt.setAuthnInstant(new DateTime());

		AuthnContext authContext = new AuthnContextBuilder().buildObject();
		AuthnContextClassRef authCtxClassRef = new AuthnContextClassRefBuilder().buildObject();
		authCtxClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
		authContext.setAuthnContextClassRef(authCtxClassRef);
		authStmt.setAuthnContext(authContext);
		samlAssertion.getAuthnStatements().add(authStmt);

		if (customAttributes != null) {
			samlAssertion.getAttributeStatements().add(buildAttributeStatement(customAttributes));
		}

		AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
		Audience issuerAudience = new AudienceBuilder().buildObject();
		issuerAudience.setAudienceURI(audienceURI);
		audienceRestriction.getAudiences().add(issuerAudience);

		Conditions conditions = new ConditionsBuilder().buildObject();
		conditions.setNotBefore(currentTime);
		conditions.setNotOnOrAfter(notOnOrAfter);
		conditions.getAudienceRestrictions().add(audienceRestriction);
		samlAssertion.setConditions(conditions);

		if (sign) {
			setSignature(samlAssertion, privateKey, certificate);
		}

		return samlAssertion;
	}

	public static Assertion setSignature(Assertion assertion, X509Credential signingCredential,
			java.security.cert.Certificate certificate) throws Exception {
		// SAMLSSOUtil.doBootstrap();
		try {
			Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
			signature.setSigningCredential(signingCredential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

			try {
				KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
				X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
				X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);
				cert.setValue(org.apache.xml.security.utils.Base64.encode(certificate.getEncoded()));
				data.getX509Certificates().add(cert);
				keyInfo.getX509Datas().add(data);
				signature.setKeyInfo(keyInfo);
			} catch (Exception e) {
				e.printStackTrace();
				throw new Exception("errorGettingCert");
			}

			assertion.setSignature(signature);

			List<Signature> signatureList = new ArrayList<Signature>();
			signatureList.add(signature);

			// Marshall and Sign
			MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
			Marshaller marshaller = marshallerFactory.getMarshaller(assertion);

			marshaller.marshall(assertion);

			org.apache.xml.security.Init.init();
			Signer.signObjects(signatureList);
			return assertion;

		} catch (Exception e) {
			throw new Exception("Error while signing the SAML Response message.", e);
		}
	}

	private Map<String, String> getAttributes() {
		Map<String, String> customAttributes = new HashMap<String, String>();
		customAttributes.put("FirstName", "John");
		customAttributes.put("LastName", "Smith");
		customAttributes.put("Email", "john.smith@yahoo.com");
		customAttributes.put("PhoneNumber", "76373898998");
		customAttributes.put("Locality", "USA");
		customAttributes.put("Username", "John.Smith");
		return customAttributes;
	}

	/**
	 * Build Attribute Statement
	 * 
	 * @param claims
	 * @return AttributeStatement
	 */
	@SuppressWarnings("rawtypes")
	private AttributeStatement buildAttributeStatement(Map<String, String> claims) {
		AttributeStatement attStmt = null;
		if (claims != null) {
			attStmt = new AttributeStatementBuilder().buildObject();
			Iterator<String> ite = claims.keySet().iterator();

			for (int i = 0; i < claims.size(); i++) {
				Attribute attrib = new AttributeBuilder().buildObject();
				String claimUri = ite.next();
				attrib.setName(claimUri);
				// Set custom Attributes
				XMLObjectBuilder stringBuilder = builderFactory.getBuilder(XSString.TYPE_NAME);
				XSString stringValue = (XSString) stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
						XSString.TYPE_NAME);
				stringValue.setValue(claims.get(claimUri));
				attrib.getAttributeValues().add(stringValue);
				attStmt.getAttributes().add(attrib);
			}
		}
		return attStmt;
	}

	private String printResponse(Response response) throws Exception {
		System.out.println("Encrypted Assertion:");
		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(response);
		Element element = marshaller.marshall(response);
		System.out.println(XMLHelper.prettyPrintXML(element));
		return XMLHelper.prettyPrintXML(element);
	}

	public Element getPlainElement(Assertion assertion) throws Exception {
		AssertionMarshaller marshaller = new AssertionMarshaller();
		Element plaintextElement = marshaller.marshall(assertion);
		return plaintextElement;
	}

	public String printAssertion(Element plaintextElement) throws Exception {
		System.out.println("Assertion:");
		System.out.println(XMLHelper.prettyPrintXML(plaintextElement));
		return XMLHelper.prettyPrintXML(plaintextElement);
	}

	public java.security.cert.Certificate getCertificate(String file) throws Exception {
		// Get Public Key
		InputStream inStream = getClass().getResourceAsStream(file);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		java.security.cert.Certificate cert = cf.generateCertificate(inStream);
		inStream.close();
		return cert;
	}

	private static String createID() {

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
	public Issuer getIssuer() {
		Issuer issuer = new IssuerBuilder().buildObject();
		issuer.setValue(issuerString);
		issuer.setFormat(NameIDType.ENTITY);
		return issuer;
	}

	private Element getResponseData(String data) throws Exception {
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

	private Response getResponse(Element element) throws Exception {
		// Unmarshall
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		return (Response) unmarshaller.unmarshall(element);
	}

	public Map<String, String> getSAMLProperties(Assertion assertion) {
		Map<String, String> samlAttributes = new HashMap<String, String>();

		samlAttributes.put("ID", assertion.getID());
		samlAttributes.put("NameID", assertion.getSubject().getNameID().getValue());
		samlAttributes.put("Format", assertion.getSubject().getNameID().getFormat());
		samlAttributes.put("Issuer", assertion.getIssuer().getValue());
		samlAttributes.put("IssueInstant", assertion.getIssueInstant().toString());

		for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
			for (Attribute attribute : attributeStatement.getAttributes()) {
				for (XMLObject xmlObj : attribute.getAttributeValues()) {
					if (xmlObj instanceof XSString) {
						samlAttributes.put("attribute_" + attribute.getName(), ((XSString) xmlObj).getValue());
					}
				}
			}
		}

		int i = 0;
		for (AudienceRestriction audienceRestriction : assertion.getConditions().getAudienceRestrictions()) {
			for (Audience audience : audienceRestriction.getAudiences()) {
				samlAttributes.put("Audience" + i, audience.getAudienceURI());
				i++;
			}
		}

		// TODO:read authnstatements

		return samlAttributes;
	}
	
    private boolean isDateTimeSkewValid(int skewInSec, DateTime time, String descriptor) { 
        
        DateTime current_dt_utcValue = new DateTime().withZone(DateTimeZone.UTC); 
        return time.isAfter(current_dt_utcValue.getMillis()- skewInSec * 1000) && time.isBefore(current_dt_utcValue.getMillis()+ DEFAULT_RESPONSE_SKEW * 1000); 
    }	

}
