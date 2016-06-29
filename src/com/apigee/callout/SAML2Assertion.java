package com.apigee.callout;

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

import org.apache.commons.io.IOUtils;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
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

	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			e.printStackTrace();
		}
	}
	
	public SAML2Assertion() {
		//default expiry
		expiry = 60 * 60 * 1000;
	}

	public static void main(String[] args) throws Exception {
		String privateKeyFile = "/resources/pkcs8.key";
		//String publicKeyFile = "/resources/public.pem";
		String publicKeyFile = "/resources/sei_public.pem";
		
		//String sampleSAML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<saml2p:Response Destination=\"http://www.apigee.com/\"\r\n    ID=\"befegpfjobiifeekhkkgidekbkmilfbllidkjnkm\"\r\n    IssueInstant=\"2016-06-29T15:11:51.916Z\" Version=\"2.0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\">\r\n    <saml2:Issuer\r\n        Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">http://www.apigee.com/</saml2:Issuer>\r\n    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\r\n        <ds:SignedInfo>\r\n            <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\r\n            <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\r\n            <ds:Reference URI=\"#befegpfjobiifeekhkkgidekbkmilfbllidkjnkm\">\r\n                <ds:Transforms>\r\n                    <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\r\n                    <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\r\n                </ds:Transforms>\r\n                <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\r\n                <ds:DigestValue>8xDEH0SrObIrH+BFfnaIqjPzE90=</ds:DigestValue>\r\n            </ds:Reference>\r\n        </ds:SignedInfo>\r\n        <ds:SignatureValue>NP+Rb3SuxMTrQUT8Q1xsuCkrr1jQcT/uEj2LMC+WRrZD+/YoITTUp2Uz7BwbFumwOBtrCOGVGRCsjkRmzEyiEGDx6sRIjx3LAWoD6ZMSsJtwtKCRNP/gQ2N+jgarzBAhNhLa0XLvg+xBWfZDY8H5v2nm8zd9toMsp5cDomoVX3ZiNpAwo3tLA1SLe5mypFN9N5eiMdxj26V3SqoF4sJWZN7uvjzCeoPiArmNjmsatAaO5X1l6PLgxppqaiUf/3UeoMx6EuxcdLjcdMNGI0O1ENjmjGQKHDbjGiK5l9WnL3nqGEGabGmU61VFKowx2kk3jJUbpUmdCRox8YE2nyr73Q==</ds:SignatureValue>\r\n        <ds:KeyInfo>\r\n            <ds:X509Data>\r\n                <ds:X509Certificate>MIIDjTCCAnWgAwIBAgIETL7AhDANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJDQTEQMA4GA1UECBMHT250YXJpbzEQMA4GA1UEBxMHVG9yb250bzEPMA0GA1UEChMGQXBpZ2VlMRowGAYDVQQLExFTYWxlcyBFbmdpbmVlcmluZzEXMBUGA1UEAxMOd3d3LmFwaWdlZS5jb20wHhcNMTYwMTEzMTgzMjU5WhcNMTcwMTA3MTgzMjU5WjB3MQswCQYDVQQGEwJDQTEQMA4GA1UECBMHT250YXJpbzEQMA4GA1UEBxMHVG9yb250bzEPMA0GA1UEChMGQXBpZ2VlMRowGAYDVQQLExFTYWxlcyBFbmdpbmVlcmluZzEXMBUGA1UEAxMOd3d3LmFwaWdlZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCswx3c8kJvHiqlVuIKYU7tNw9trdXdfHG4ctyvtpqhLPkrw95y1CVkzuw5Oleh4pATApGoNXYa7enk5+K6FdEyO6DzcWqpBdOR5eMpbQpg/dVJ4uGITq8CaiG0+ZeLn1NJdkc4ocw4wHmKfT7Tn3cg/c0Sd5EX2BrqP1bMfP9Ceyik5KoN0kpnXz07S9DgK13KUMd7twEFuC+52bSOoox7OKnqtAX1nBHc5p7y+LYkLeAeqnkIxyfeWln/q3PULasFNASl93JjHcbr3B1gKAszG9dqmZ06Bwp51oAe+VMKm5BnzvdViJKtbCaJOgggkTjbK1PUJiy18tBpiL4VUEOpAgMBAAGjITAfMB0GA1UdDgQWBBQWaQIS4wKtvqKegdbHUT2796dDkDANBgkqhkiG9w0BAQsFAAOCAQEAjArlWVE+A5l5PQXhC3/VK+7RrenUy3iFTNMB8VcM/M1mJqbk6RjtEHqTHnUROdcMZq1yYCPEjEJ/rxQ+bYcyQHfxLLjtDshdGUaKAH8h3vL2R2t/CcXlrPONR4HE7Nb6d+dmHGjhfkvRINYRgtGGKU/UKkJg+fsSHctcFtwRsbv3+RbjmMw/Xu6Vk0wCsbr0hc7h92f5Zbyu3bZrwwZcbJsAajLpdu9foCUW1dinBDyi9cpTgCSggpvnIsesv8xz73Rf3xHReWQTDMVAwqe26d+YPiS4qvdYotqfmj8StwTqGsWHmWuT9Xn/b73j5IaOinoeCaamlGAh4X9EmnFWZg==</ds:X509Certificate>\r\n            </ds:X509Data>\r\n        </ds:KeyInfo>\r\n    </ds:Signature>\r\n    <saml2p:Status>\r\n        <saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\r\n    </saml2p:Status>\r\n    <saml2:EncryptedAssertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">\r\n        <xenc:EncryptedData Id=\"_16c4fd9473b7d18666d887e05e204c04\"\r\n            Type=\"http://www.w3.org/2001/04/xmlenc#Element\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\r\n            <xenc:EncryptionMethod\r\n                Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/>\r\n            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\r\n                <xenc:EncryptedKey\r\n                    Id=\"_9e16870a5f808de5ed416e70e61a09a7\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\r\n                    <xenc:EncryptionMethod\r\n                        Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\r\n                        <ds:DigestMethod\r\n                            Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>\r\n                    </xenc:EncryptionMethod>\r\n                    <xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\r\n                        <xenc:CipherValue>HcKCx3yMk+ytMogD5KbmsPowBtnSnYgBS2KbmckPJyRFYdnw9XUULa97elu2bgFDDRPqwrInIVS/WXebpbo4gTq3zH6jQBW2BWvXrg62ba9Eq9cgG9vEDhiXH5wjAVrYvOZgdDHF76UlRkf82ZhWD3nFYlueQtnQupmaJ7fDIFotleOC2ZLZPm12JroF4rV1nEXnJkFRKafY8dNNZyAbdddEqnolWdU2ZQv+NdZpfNkldsQQ/Xliq4mWa8DnIG0u1nKexoEEcMXHAw/Epx9wiyWgLszy/hxj9JWuy1qMbSWVwPj/73ThB8q755jrLWLGVM/99/erg1PIJw5takNDFw==</xenc:CipherValue>\r\n                    </xenc:CipherData>\r\n                </xenc:EncryptedKey>\r\n            </ds:KeyInfo>\r\n            <xenc:CipherData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\r\n                <xenc:CipherValue>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</xenc:CipherValue>\r\n            </xenc:CipherData>\r\n        </xenc:EncryptedData>\r\n    </saml2:EncryptedAssertion>\r\n</saml2p:Response>";
		String sampleSAML = "<Response xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" Destination=\"http://ssridhar-test.apigee.net/v1/loopback\" ID=\"_296d4bf7e9fea7b4f9bd7daddc11edc183b7\" IssueInstant=\"2016-06-29T18:23:47Z\" Version=\"2.0\">\r\n    <ns1:Issuer xmlns:ns1=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://test.apigee.com</ns1:Issuer>\r\n    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\r\n        <ds:SignedInfo>\r\n            <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\r\n            <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\r\n            <ds:Reference URI=\"#_296d4bf7e9fea7b4f9bd7daddc11edc183b7\">\r\n                <ds:Transforms>\r\n                    <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\r\n                    <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\r\n                </ds:Transforms>\r\n                <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\r\n                <ds:DigestValue>hSN58QCGXyCDIYDvmUhJ4YfXiaKAlmoLb1vNoco2bPs=</ds:DigestValue>\r\n            </ds:Reference>\r\n        </ds:SignedInfo>\r\n        <ds:SignatureValue>\r\ntOiSTO8JlOmMVZ2RjZAgrF1T8c6bcd1MgmZr8NzeAAyfr47oeQvO/m3Y7JuCpWMYlaBFH35Gpo2N\r\npWmfS+MQGUcdRx77abFtIyV5kGDBIpUucrq5/3K0R5Xj8kT8oSCBRVZEHa/SzG0rL05Y4wLzihIm\r\nwix/6/hhEJAt1YnsDoM=\r\n</ds:SignatureValue>\r\n        <ds:KeyInfo>\r\n            <ds:X509Data>\r\n                <ds:X509Certificate>\r\nMIICpTCCAg4CCQCTAt8Dm6chSzANBgkqhkiG9w0BAQUFADCBlTELMAkGA1UEBhMCVVMxFTATBgNV\r\nBAgTDFBlbm5zeWx2YW5pYTENMAsGA1UEBxMET2FrczEYMBYGA1UEChMPU0VJIEludmVzdG1lbnRz\r\nMQwwCgYDVQQLEwNDQVMxGzAZBgNVBAMTElNFSSBBcGFjaGUgUm9vdCBDQTEbMBkGCSqGSIb3DQEJ\r\nARYMY2FzQHNlaWMuY29tMB4XDTEyMDUzMTE3MzEzMVoXDTIyMDUyOTE3MzEzMVowgZcxCzAJBgNV\r\nBAYTAlVTMRUwEwYDVQQIEwxQZW5uc3lsdmFuaWExDTALBgNVBAcTBE9ha3MxGDAWBgNVBAoTD1NF\r\nSSBJbnZlc3RtZW50czEMMAoGA1UECxMDQ0FTMR0wGwYDVQQDExRzbXBvbGljeWRldi5zZWljLmNv\r\nbTEbMBkGCSqGSIb3DQEJARYMY2FzQHNlaWMuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\r\ngQDtpiw6Nu7AJ6kxdVYoDIMoJOAMA24JL89rWPo/zmv6UjplOl7g/G9AVZjr17/cAJIrWeLkuepA\r\nknmc9DxDT5UAcn/Yf9rfKtRnVAWNg9G62+JZSrN4hZeZcJJB7BAorgeqLE0TJITsQVp8mJfygSqQ\r\nUmQiEkW0HJJPYua2lrCogwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBADtDyeuEq9UEYXP523qukGqz\r\nH+YyaNGNawDSwfOv9qersW5lLqY3A9zpulVb1Y49fN2ddZyuBXrTQ6P1f82rLFdqbySE6QlomtoO\r\nFrPufK4OhQxcfx0Uo1JM9pw6vAtAdPk8JsI9J3fH8Df3uSRV4NzouDniTNSW38Sadt3BIkFH\r\n</ds:X509Certificate>\r\n            </ds:X509Data>\r\n        </ds:KeyInfo>\r\n    </ds:Signature>\r\n    <Status>\r\n        <StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\r\n    </Status>\r\n    <ns2:Assertion xmlns:ns2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_0ab596698db1eeb8c73f5a3bfae81ffbdead\" IssueInstant=\"2016-06-29T18:23:47Z\" Version=\"2.0\">\r\n        <ns2:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://test.apigee.com</ns2:Issuer>\r\n        <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\r\n            <ds:SignedInfo>\r\n                <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\r\n                <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\r\n                <ds:Reference URI=\"#_0ab596698db1eeb8c73f5a3bfae81ffbdead\">\r\n                    <ds:Transforms>\r\n                        <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\r\n                        <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\r\n                    </ds:Transforms>\r\n                    <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\r\n                    <ds:DigestValue>zH2U121iumAZJ5/aw+sCwQloQV0BIfg+VZBMQjtuX8w=</ds:DigestValue>\r\n                </ds:Reference>\r\n            </ds:SignedInfo>\r\n            <ds:SignatureValue>\r\nY4EvDTmWlFbWNbQtOgVOiZsceSgFcX9ZofkQIMpPT9jX67dSQkUNj91BbOO+LdOeJetISLe0Yo+Y\r\nFuhFYGEbqvT958C3a/9HdzCoS7mtqMIYMaKdgK7IqzH934uhuOljwRmhiIE1tsya2CpffDk+3+L9\r\nUUExJpHa5/wYn3mMiT8=\r\n</ds:SignatureValue>\r\n            <ds:KeyInfo>\r\n                <ds:X509Data>\r\n                    <ds:X509Certificate>\r\nMIICpTCCAg4CCQCTAt8Dm6chSzANBgkqhkiG9w0BAQUFADCBlTELMAkGA1UEBhMCVVMxFTATBgNV\r\nBAgTDFBlbm5zeWx2YW5pYTENMAsGA1UEBxMET2FrczEYMBYGA1UEChMPU0VJIEludmVzdG1lbnRz\r\nMQwwCgYDVQQLEwNDQVMxGzAZBgNVBAMTElNFSSBBcGFjaGUgUm9vdCBDQTEbMBkGCSqGSIb3DQEJ\r\nARYMY2FzQHNlaWMuY29tMB4XDTEyMDUzMTE3MzEzMVoXDTIyMDUyOTE3MzEzMVowgZcxCzAJBgNV\r\nBAYTAlVTMRUwEwYDVQQIEwxQZW5uc3lsdmFuaWExDTALBgNVBAcTBE9ha3MxGDAWBgNVBAoTD1NF\r\nSSBJbnZlc3RtZW50czEMMAoGA1UECxMDQ0FTMR0wGwYDVQQDExRzbXBvbGljeWRldi5zZWljLmNv\r\nbTEbMBkGCSqGSIb3DQEJARYMY2FzQHNlaWMuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\r\ngQDtpiw6Nu7AJ6kxdVYoDIMoJOAMA24JL89rWPo/zmv6UjplOl7g/G9AVZjr17/cAJIrWeLkuepA\r\nknmc9DxDT5UAcn/Yf9rfKtRnVAWNg9G62+JZSrN4hZeZcJJB7BAorgeqLE0TJITsQVp8mJfygSqQ\r\nUmQiEkW0HJJPYua2lrCogwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBADtDyeuEq9UEYXP523qukGqz\r\nH+YyaNGNawDSwfOv9qersW5lLqY3A9zpulVb1Y49fN2ddZyuBXrTQ6P1f82rLFdqbySE6QlomtoO\r\nFrPufK4OhQxcfx0Uo1JM9pw6vAtAdPk8JsI9J3fH8Df3uSRV4NzouDniTNSW38Sadt3BIkFH\r\n</ds:X509Certificate>\r\n                </ds:X509Data>\r\n            </ds:KeyInfo>\r\n        </ds:Signature>\r\n        <ns2:Subject>\r\n            <ns2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">jhynes</ns2:NameID>\r\n            <ns2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\r\n                <ns2:SubjectConfirmationData NotOnOrAfter=\"2016-06-29T18:25:17Z\" Recipient=\"http://ssridhar-test.apigee.net/v1/loopback\"/>\r\n            </ns2:SubjectConfirmation>\r\n        </ns2:Subject>\r\n        <ns2:Conditions NotBefore=\"2016-06-29T18:23:17Z\" NotOnOrAfter=\"2016-06-29T18:25:17Z\">\r\n            <ns2:AudienceRestriction>\r\n                <ns2:Audience>https://apigee.seic.com</ns2:Audience>\r\n            </ns2:AudienceRestriction>\r\n        </ns2:Conditions>\r\n        <ns2:AuthnStatement AuthnInstant=\"2016-06-29T18:23:46Z\" SessionIndex=\"/A3qx/QZm4Hg/LcOwbx1DxVkSEM=ha7Qog==\" SessionNotOnOrAfter=\"2016-06-29T18:25:17Z\">\r\n            <ns2:AuthnContext>\r\n                <ns2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</ns2:AuthnContextClassRef>\r\n            </ns2:AuthnContext>\r\n        </ns2:AuthnStatement>\r\n    </ns2:Assertion>\r\n</Response>";

		SAML2Assertion saml = new SAML2Assertion();
		BasicX509Credential publicKey = saml.getPublicKey(publicKeyFile);
		BasicX509Credential privateKey = saml.getCredentials(privateKeyFile);
		Certificate certificate = saml.getCertificate(publicKeyFile);

		saml.setAudienceURI("http://www.apigee.com/");
		saml.setDestination("http://www.apigee.com/");
		saml.setRecepient("http://www.apigee.com/");
		saml.setIssuerString("http://www.apigee.com/");

		/*Response response = saml.buildSAMLResponse(true, true, "ssridhar@apigee.com", saml.getAttributes(), publicKey,
				privateKey, certificate);
		saml.printResponse(response);

		Assertion assertion = saml.decrypt(response.getEncryptedAssertions().get(0), privateKeyFile);*/
		
		Assertion assertion = saml.decrypt(sampleSAML, privateKeyFile);
		if (!saml.verifyAssertion(assertion, publicKeyFile)) {
			throw new ValidationException("signature not valid!");
		}
		Element plaintext = saml.getPlainElement(assertion);
		saml.printAssertion(plaintext);

		System.out.println(saml.getSAMLProperties(assertion));

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

	public BasicX509Credential getPublicKey(String publicKeyFileName) throws Exception {
		// Get Public Key
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

	public BasicX509Credential getCredentials(String privateKeyFileName) throws Exception {
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

	public boolean verifyAssertion(Assertion assertion, String publicKeyFile) throws Exception {
		return verifyAssertion(assertion, getPublicKey(publicKeyFile));
	}
	
	public boolean verifyAssertion(Assertion assertion, Credential validatingCredential) throws Exception {
		SignatureValidator signatureValidator = new SignatureValidator(validatingCredential);
		if (assertion.getSignature() != null) {
			signatureValidator.validate(assertion.getSignature());
		}
		if (assertion.getConditions().getNotBefore() != null && assertion.getConditions().getNotBefore().isAfterNow()) {
		    throw new ValidationException("Condition states that assertion is not yet valid");
		}

		if (assertion.getConditions().getNotOnOrAfter() != null
		                && (assertion.getConditions().getNotOnOrAfter().isBeforeNow() || assertion.getConditions().getNotOnOrAfter().isEqualNow())) {
		    throw new ValidationException("Condition states that assertion is no longer valid");
		}		
		return true;
	}

	public Assertion decrypt(String encryptedResponse, String privateKeyFile) throws Exception {
		return decrypt(encryptedResponse, getCredentials(privateKeyFile));
	}
	
	public Assertion decrypt (String encryptedResponse, BasicX509Credential privateKey) throws Exception {
		Element element = getResponseData(encryptedResponse);
		Response response = getResponse(element);

		if (!response.getEncryptedAssertions().isEmpty()) {
			return decrypt(response.getEncryptedAssertions().get(0), privateKey);
		}
		else {
			return response.getAssertions().get(0);
		}
	}
	
	public Assertion decrypt(EncryptedAssertion encryptedAssertion, String privateKeyFile) throws Exception {
		return decrypt(encryptedAssertion, getCredentials(privateKeyFile));
	}
	
	public Assertion decrypt(EncryptedAssertion encryptedAssertion, BasicX509Credential privateKey) throws Exception {
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
		Map<String, String> customAttributes = new HashMap<String,String>();
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
		Map <String, String> samlAttributes = new HashMap<String, String>();
		
		samlAttributes.put("ID", assertion.getID());
		samlAttributes.put("NameID", assertion.getSubject().getNameID().getValue());
		samlAttributes.put("Format", assertion.getSubject().getNameID().getFormat());
		samlAttributes.put("Issuer", assertion.getIssuer().getValue());
		samlAttributes.put("IssueInstant", assertion.getIssueInstant().toString());
		
		for (AttributeStatement attributeStatement : assertion.getAttributeStatements()){
			for (Attribute attribute : attributeStatement.getAttributes()) {
				for (XMLObject xmlObj : attribute.getAttributeValues()) {
					if (xmlObj instanceof XSString) {
						samlAttributes.put("attribute_"+attribute.getName(), ((XSString) xmlObj).getValue());
					}
				}
			}
		}
		
		//TODO:read authnstatements
		
		return samlAttributes;
	}

}
