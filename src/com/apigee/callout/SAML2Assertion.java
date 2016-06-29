package com.apigee.callout;



import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.xml.namespace.QName;

import org.apache.commons.io.IOUtils;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
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
import org.opensaml.saml2.core.NameID;
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
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
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
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class SAML2Assertion {
	
	public static final String SUCCESS_CODE = "urn:oasis:names:tc:SAML:2.0:status:Success"; 
	public static final String SUBJECT_CONFIRM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

	public static void main(String[] args) throws Exception{
		String privateKeyFileName = "/resources/pkcs8.key";
		String publicKeyFileName = "/resources/public.pem";
		String validatingCredFileName = "/resources/keystore.jks";
		String password = "admin123";
		String certificateAliasName = "selfsigned";
		
		SAML2Assertion saml = new SAML2Assertion();
		BasicX509Credential publicKey = saml.getPublicKey(publicKeyFileName);
		BasicX509Credential privateKey = saml.getCredentials(privateKeyFileName);
		Certificate certificate = saml.getCertificate(publicKeyFileName);

		Response response = saml.buildSAMLResponse(true, true, "ssridhar@apigee.com", publicKey, privateKey, certificate);
		saml.printResponse(response);
		
		Assertion assertion = saml.decrypt(response.getEncryptedAssertions().get(0), privateKey);
		if (!saml.verifySignature(response, assertion, publicKey)) {
			System.out.println("signature not valid!");
		}
		Element plaintext = saml.getPlainElement(assertion);
		saml.printAssertion(plaintext);
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
	
	public boolean verifySignature (Response response, Assertion assertion, Credential validatingCredential) throws Exception{
        SignatureValidator signatureValidator = new SignatureValidator(validatingCredential);
        if (response.getSignature()!=null) {
    		signatureValidator.validate(response.getSignature());		
        }
        if (assertion.getSignature()!=null) {
    		signatureValidator.validate(assertion.getSignature());		
        }
        return true;
	}
	
	public Assertion decrypt(EncryptedAssertion encryptedAssertion, BasicX509Credential privateKey) throws Exception {
	     KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(privateKey);

         EncryptedKey key = encryptedAssertion.getEncryptedData().
                 getKeyInfo().getEncryptedKeys().get(0);		
         Decrypter decrypter = new Decrypter(null, keyResolver, null);
         SecretKey dkey = (SecretKey) decrypter.decryptKey(key, encryptedAssertion.getEncryptedData().
                 getEncryptionMethod().getAlgorithm());  
         Credential shared = SecurityHelper.getSimpleCredential(dkey);
         decrypter = new Decrypter(new StaticKeyInfoCredentialResolver(shared), keyResolver, null);
         decrypter.setRootInNewDocument(true);
		 return decrypter.decrypt(encryptedAssertion);
	}
	
	public Response buildSAMLResponse(boolean sign, boolean encrypt, String userName, BasicX509Credential publicKey, BasicX509Credential privateKey, Certificate certificate) throws Exception {
		Response response = new org.opensaml.saml2.core.impl.ResponseBuilder().buildObject();
        response.setIssuer(SAMLSSOUtil.getIssuer()); 
        response.setID(SAMLSSOUtil.createID()); 
        response.setDestination("http://www.apigee.com/about"); 
        response.setStatus(buildStatus(SUCCESS_CODE, null)); 
        response.setVersion(SAMLVersion.VERSION_20); 
        DateTime issueInstant = new DateTime(); 
        DateTime notOnOrAfter = 
                new DateTime(issueInstant.getMillis() + 
                        60 * 60 * 1000);
        response.setIssueInstant(issueInstant); 
        Assertion assertion = buildSAMLAssertion(notOnOrAfter, userName, privateKey, certificate); 
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
	
	
	/**
	 * Sign the SAML Response message
	 * 
	 * @param response
	 * @param signatureAlgorithm
	 * @param cred
	 * @return
	 * @throws IdentityException
	 */
	public static Response setSignature(Response response, X509Credential signingCredential, java.security.cert.Certificate certificate) throws Exception {
		SAMLSSOUtil.doBootstrap();
		try {
			Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
			signature.setSigningCredential(signingCredential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

			try {
        		// This is also the default if a null SecurityConfiguration is specified
        		/*SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
        		NamedKeyInfoGeneratorManager namedKeyInfoGeneratorManager = secConfig.getKeyInfoGeneratorManager(); 
        		KeyInfoGeneratorManager keyInfoGeneratorManager = namedKeyInfoGeneratorManager.getDefaultManager();
        		KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(signingCredential);
        		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();*/
				KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
				X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
				X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);	
				cert.setValue(org.apache.xml.security.utils.Base64.encode(certificate.getEncoded()));
				data.getX509Certificates().add(cert);
				keyInfo.getX509Datas().add(data);
				//KeyInfo keyInfo = keyInfoGenerator.generate(signingCredential);
				signature.setKeyInfo(keyInfo);
			} catch (Exception e) {
				throw new Exception("errorGettingCert");
			}

			response.setSignature(signature);

			List<Signature> signatureList = new ArrayList<Signature>();
			signatureList.add(signature);

			// Marshall and Sign
			MarshallerFactory marshallerFactory =
			                                      org.opensaml.xml.Configuration.getMarshallerFactory();
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
	 * @throws IdentityException
	 */
	private static XMLObject buildXMLObject(QName objectQName) throws Exception {
		XMLObjectBuilder<XMLObject> builder =
		                           org.opensaml.xml.Configuration.getBuilderFactory()
		                                                         .getBuilder(objectQName);
		if (builder == null) {
			throw new Exception("Unable to retrieve builder for object QName " +
			                            objectQName);
		}
		return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(),
		                           objectQName.getPrefix());
	}	
	
	/**
     * Build SAML assertion 
     * 
     * @param ssoIdPConfigs 
     * @param notOnOrAfter 
     * @param userName 
     * @return Assertion object 
     * @throws IdentityException 
     */ 
    private Assertion buildSAMLAssertion(DateTime notOnOrAfter, String userName, BasicX509Credential privateKey, Certificate certificate) 
            throws Exception { 
        DateTime currentTime = new DateTime(); 
        Assertion samlAssertion = new AssertionBuilder().buildObject(); 
        samlAssertion.setID(SAMLSSOUtil.createID()); 
        samlAssertion.setVersion(SAMLVersion.VERSION_20); 
        samlAssertion.setIssuer(SAMLSSOUtil.getIssuer()); 
        samlAssertion.setIssueInstant(currentTime); 
        Subject subject = new SubjectBuilder().buildObject(); 
        NameID nameId = new NameIDBuilder().buildObject();  
 
        nameId.setValue(userName); 
        nameId.setFormat(NameIdentifier.EMAIL); 
        subject.setNameID(nameId); 
 
        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject(); 
        subjectConfirmation.setMethod(SUBJECT_CONFIRM_BEARER); 
 
        SubjectConfirmationData subjectConfirmationData = 
                new SubjectConfirmationDataBuilder().buildObject(); 
        subjectConfirmationData.setRecipient("http://www.apigee.com/about"); 
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
 
        Map<String, String> claims = getAttributes(); 
        if (claims != null) { 
            //samlAssertion.getAttributeStatements().add(buildAttributeStatement(claims)); 
        } 
 
        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject(); 
        Audience issuerAudience = new AudienceBuilder().buildObject(); 
        issuerAudience.setAudienceURI("http://www.apigee.com/about"); 
        audienceRestriction.getAudiences().add(issuerAudience); 
 
        Conditions conditions = new ConditionsBuilder().buildObject(); 
        conditions.setNotBefore(currentTime); 
        conditions.setNotOnOrAfter(notOnOrAfter); 
        conditions.getAudienceRestrictions().add(audienceRestriction); 
        samlAssertion.setConditions(conditions); 
 
        setSignature(samlAssertion, privateKey, certificate);
 
        return samlAssertion; 
    } 	
    
    public static Assertion setSignature(Assertion assertion, X509Credential signingCredential, java.security.cert.Certificate certificate) throws Exception {
    	SAMLSSOUtil.doBootstrap();
        try {
            Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
            signature.setSigningCredential(signingCredential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            try {
        		// This is also the default if a null SecurityConfiguration is specified
        		/*SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
        		NamedKeyInfoGeneratorManager namedKeyInfoGeneratorManager = secConfig.getKeyInfoGeneratorManager(); 
        		KeyInfoGeneratorManager keyInfoGeneratorManager = namedKeyInfoGeneratorManager.getDefaultManager();
        		KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(signingCredential);
        		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();*/
				KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
				X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
				X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);
				cert.setValue(org.apache.xml.security.utils.Base64.encode(certificate.getEncoded()));
				data.getX509Certificates().add(cert);
				keyInfo.getX509Datas().add(data);
				//KeyInfo keyInfo = keyInfoGenerator.generate(signingCredential);
				signature.setKeyInfo(keyInfo);
            } catch (Exception e) {
            	e.printStackTrace();
                throw new Exception("errorGettingCert");
            }

            assertion.setSignature(signature);

            List<Signature> signatureList = new ArrayList<Signature>();
            signatureList.add(signature);

            // Marshall and Sign
            MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration
                    .getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(assertion);

            marshaller.marshall(assertion);

            org.apache.xml.security.Init.init();
            Signer.signObjects(signatureList);
            return assertion;

        } catch (Exception e) {
            throw new Exception("Error while signing the SAML Response message.", e);
        }
    }   
    
    private Map<String, String> getAttributes () {
		Map<String,String> customAttributes = new HashMap<String, String>();
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
    private AttributeStatement buildAttributeStatement(Map<String, String> claims) { 
        AttributeStatement attStmt = null; 
        if (claims != null) { 
            attStmt = new AttributeStatementBuilder().buildObject(); 
            Iterator<String> ite = claims.keySet().iterator(); 
 
            for (int i = 0; i < claims.size(); i++) { 
                Attribute attrib = new AttributeBuilder().buildObject(); 
                String claimUri = ite.next(); 
                attrib.setName(claimUri); 
                // look 
                // https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUsrManJavaAnyTypes 
                XSStringBuilder stringBuilder = 
                        (XSStringBuilder) Configuration.getBuilderFactory() 
                                .getBuilder(XSString.TYPE_NAME); 
                XSString stringValue = 
                        stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, 
                                XSString.TYPE_NAME); 
                stringValue.setValue(claims.get(claimUri)); 
                attrib.getAttributeValues().add(stringValue); 
                attStmt.getAttributes().add(attrib); 
            } 
        } 
        return attStmt; 
    } 
    
	private String printResponse (Response response) throws Exception{
		System.out.println("Encrypted Assertion:");
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(response);
        Element element = marshaller.marshall(response);
        System.out.println(XMLHelper.prettyPrintXML(element));
		return XMLHelper.prettyPrintXML(element);
	}
	
	private Element getPlainElement (Assertion assertion) throws Exception {
		AssertionMarshaller marshaller = new AssertionMarshaller();
		Element plaintextElement = marshaller.marshall(assertion);
		return plaintextElement;
	}
	
	private String printAssertion(Element plaintextElement) throws Exception {
		System.out.println("Assertion:");
		System.out.println(XMLHelper.prettyPrintXML(plaintextElement));
		return XMLHelper.prettyPrintXML(plaintextElement);
	}	
	
	private java.security.cert.Certificate getCertificate(String file) throws Exception{
		//Get Public Key
		InputStream inStream = getClass().getResourceAsStream(file);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		java.security.cert.Certificate cert = cf.generateCertificate(inStream);
		inStream.close();
		return cert;
	}
}
