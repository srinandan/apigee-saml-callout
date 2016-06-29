package com.apigee.callout;

import java.util.Map;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

public class SAMLDecryptAssertion implements Execution {

	@Override
	public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {

		try {
			String encAssertion = messageContext.getMessage().getContent();
			String privateKeyFile = "/resources/pkcs8.key";
			String publicKeyFile = "/resources/public.pem";
			
			SAML2Assertion saml = new SAML2Assertion();
			
			Assertion decryptedAssertion = saml.decrypt(encAssertion, privateKeyFile);
			if (!saml.verifyAssertion(decryptedAssertion, publicKeyFile)) {
				throw new ValidationException("signature not valid!");
			}
			
			Element plaintext = saml.getPlainElement(decryptedAssertion);
			Map<String, String> attributeAssertions = saml.getCustomAttributes(plaintext);

			for (Map.Entry<String, String> entry : attributeAssertions.entrySet()) {
				String key = entry.getKey();
				String providedValue = entry.getValue();
				messageContext.setVariable("saml_attribute_" + key, providedValue);
			}
			
			messageContext.setVariable("saml_issuer", saml.getIssuer(plaintext));
			messageContext.setVariable("saml_subject", saml.getSubjectName(plaintext));
			messageContext.setVariable("saml_assertion", saml.printAssertion(plaintext));
			return ExecutionResult.SUCCESS;
		} catch (Throwable e) {
			e.printStackTrace();
			messageContext.setVariable("_error", e.getMessage());
			messageContext.setVariable("_stacktrace", ExceptionUtils.getStackTrace(e));
			return ExecutionResult.ABORT;
		}
	}

}
