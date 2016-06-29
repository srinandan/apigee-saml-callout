package com.apigee.callout;

import java.util.Map;

import org.apache.commons.lang.exception.ExceptionUtils;
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
			
			SAMLAssertion saml = new SAMLAssertion();
			Element decryptedAssertion = saml.decrypt(encAssertion, privateKeyFile, publicKeyFile);
			Map<String, String> attributeAssertions = saml.getAttributes(decryptedAssertion);
			for (Map.Entry<String, String> entry : attributeAssertions.entrySet()) {
				String key = entry.getKey();
				String providedValue = entry.getValue();
				messageContext.setVariable("saml_attribute_" + key, providedValue);
			}
			messageContext.setVariable("saml_issuer", saml.getIssuer(decryptedAssertion));
			messageContext.setVariable("saml_subject", saml.getSubjectName(decryptedAssertion));
			messageContext.setVariable("saml_assertion", saml.printAssertion(decryptedAssertion));
			return ExecutionResult.SUCCESS;
		} catch (Throwable e) {
			e.printStackTrace();
			messageContext.setVariable("_error", e.getMessage());
			messageContext.setVariable("_stacktrace", ExceptionUtils.getStackTrace(e));
			return ExecutionResult.ABORT;
		}
	}

}
